--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

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
    error("[record_utils]: expected string or userdata")
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

local function u16(n)
  return chr((n >> 8) & 0xff, n & 0xff)
end

function M.client_hello_record(hs, host)
  if not hs or type(hs.client_hello) ~= "function" then
    error("[record_utils.client_hello_record]: invalid handshake object")
  end
  local msg = to_udata(hs:client_hello(host))
  local rec = {
    type = constants.content_type.handshake,
    version = constants.version.TLS1_0,
    length = #msg,
    body = msg,
  }
  local bytes = userdata("u8", 5 + #msg)
  bytes:set(0,
    rec.type,
    (rec.version >> 8) & 0xff,
    rec.version & 0xff,
    (rec.length >> 8) & 0xff,
    rec.length & 0xff)
  bytes:set(5, msg:get(0, #msg))
  rec.bytes = bytes
  return rec
end

function M.parse_records(data)
  local buf = to_udata(data)
  local records = {}
  local pos = 0
  local idx = 1
  while pos + 5 <= #buf do
    local typ = buf:get(pos)
    local ver = (buf:get(pos + 1) << 8) | buf:get(pos + 2)
    local len = (buf:get(pos + 3) << 8) | buf:get(pos + 4)
    if pos + 5 + len > #buf then break end
    local body = userdata("u8", len)
    body:set(0, buf:get(pos + 5, len))
    local bytes = userdata("u8", 5 + len)
    bytes:set(0, buf:get(pos, 5 + len))
    records[#records + 1] = {
      type = typ,
      version = ver,
      length = len,
      body = body,
      bytes = bytes,
    }
    pos = pos + 5 + len
    idx = idx + 1
  end
  return records
end

return M
