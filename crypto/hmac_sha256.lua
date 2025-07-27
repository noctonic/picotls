--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

M.DIGEST_SIZE = sha256.DIGEST_SIZE
M.BLOCK_SIZE = sha256.BLOCK_SIZE

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
    error("[hmac_sha256]: expected string or userdata")
  end
end

local function init_ctx(ctx, key)
  local k = to_userdata(key or "")
  if #k > M.BLOCK_SIZE then
    k = sha256.new(k):udigest()
  else
    local tmp = userdata("u8", #k)
    if #k > 0 then
      tmp:set(0, k:get(0, #k))
    end
    k = tmp
  end
  ctx.ipad = userdata("u8", M.BLOCK_SIZE)
  ctx.opad = userdata("u8", M.BLOCK_SIZE)
  for i=0,M.BLOCK_SIZE-1 do
    local byte = i < #k and k:get(i) or 0
    ctx.ipad:set(i, byte ~ 0x36)
    ctx.opad:set(i, byte ~ 0x5c)
  end
  ctx.inner = sha256.new()
  ctx.inner:update(ctx.ipad)
  ctx._digest = nil
end

function M.new(key, data)
  local ctx = {}
  init_ctx(ctx, key)

  function ctx:update(chunk)
    ctx.inner:update(chunk)
  end

  function ctx:reset(new_key)
    init_ctx(ctx, new_key or key)
  end

  function ctx:udigest()
    if not ctx._digest then
      local inner_hash = ctx.inner:udigest()
      local outer = sha256.new()
      outer:update(ctx.opad)
      outer:update(inner_hash)
      ctx._digest = outer:udigest()
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
      t[#t+1]=string.format("%02x", ud:get(i))
    end
    return table.concat(t, "")
  end

  if data then
    ctx:update(data)
  end

  return ctx
end

return M
