--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

local function to_udata(data)
  if type(data) == "string" then
    local u = userdata("u8", #data)
    if #data > 0 then u:set(0, ord(data, 1, #data)) end
    return u
  elseif type(data) == "userdata" then
    data:mutate("u8", #data)
    return data
  else
    error("[tls_socket]: expected string or userdata")
  end
end

local function u24(n)
  return chr((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
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

local function parse_records(buf)
  buf = to_udata(buf)
  local records = {}
  local pos = 0
  while pos + 5 <= #buf do
    local typ = buf:get(pos)
    local ver = (buf:get(pos + 1) << 8) | buf:get(pos + 2)
    local len = (buf:get(pos + 3) << 8) | buf:get(pos + 4)
    if pos + 5 + len > #buf then break end
    local body = userdata("u8", len)
    body:set(0, buf:get(pos + 5, len))
    local bytes = userdata("u8", 5 + len)
    bytes:set(0, buf:get(pos, 5 + len))
    records[#records+1] = {type=typ, version=ver, length=len, body=body, bytes=bytes}
    pos = pos + 5 + len
  end
  local leftover = ""
  if pos < #buf then
    local tmp = userdata("u8", #buf - pos)
    tmp:set(0, buf:get(pos, #buf - pos))
    leftover = chr(tmp:get())
  end
  return records, leftover
end

local Conn = {}
Conn.__index = Conn

function Conn:write(data)
  local dtype = type(data)
  local dlen = dtype == "string" and #data or #data
  local rec = self._enc:seal(constants.content_type.application_data, data)
  self._sock:write(rec)
end

function Conn:status()
  return self._sock:status()
end

function Conn:_pull()
  local chunk
  while self._sock:status() == 'ready' and not chunk do
    chunk = self._sock:read()
  end
  if not chunk then return end
  self._rbuf = self._rbuf .. chunk
  while true do
    chunk = self._sock:read()
    if not chunk then break end
    self._rbuf = self._rbuf .. chunk
  end
end

function Conn:read()
  if #self._rbuf == 0 and self._sock:status() == 'ready' then
    self:_pull()
  end
  local out = ""
  repeat
    local records, rest = parse_records(self._rbuf)
    self._rbuf = rest
    for _,r in ipairs(records) do
      if r.type == constants.content_type.application_data then
        local pt, typ = self._dec:open(r.bytes)
        if pt then
          if typ == constants.content_type.application_data then
            out = out .. pt
          elseif typ == constants.content_type.handshake then
            local htype = ord(pt,1)
            if htype == constants.handshake_type.new_session_ticket then
            end
          end
        end
      end
    end
    if #out > 0 then break end
    if self._sock:status() ~= 'ready' then break end
    self:_pull()
  until #out > 0 or #self._rbuf == 0
  if #out > 0 then
    --printh(string.format("[tls_socket.read] out len=%d", #out))
    return out
  else
    -- printh("[tls_socket.read] out nil")
    return nil
  end
end

function Conn:close()
  local alert = chr(constants.alert_level.warning,
                    constants.alert_description.close_notify)
  local rec = self._enc:seal(constants.content_type.alert, alert)
  self._sock:write(rec)
  self._sock:close()
end

function M.connect(host, port)
  local sock, err = socket("tcp://"..host..":"..port)
  if not sock then error("[tls_socket.connect]: "..tostring(err)) end
  --printh("[tls_socket] connected tcp://"..host..":"..port)
  local hs = handshake.new{    
    --client_random = userdata("u8",32,"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    --private_key =   userdata("u8",32,"e81ea2b8c3c140f47cc67dfb20aeeb77e4db7ab5a6d1f605006ebe35a4768846"),
    compatibility_mode = false
  }

  local rec = record_utils.client_hello_record(hs, nil)
  local ch = rec.body
  local ud = rec.bytes

  if #ud >= 5 then
    local rtype = ud:get(0)
    local ver = (ud:get(1) << 8) | ud:get(2)
    local len = (ud:get(3) << 8) | ud:get(4)
    if rtype == constants.content_type.handshake and #ud >= 5 + len then
      local hs_type = ud:get(5)
    end
  end
  sock:write(chr(ud:get()))

  local rbuf = ""
  local records, rest

  repeat
    local chunk
    while sock:status() == 'ready' and not chunk do
      chunk = sock:read()
    end
    if not chunk then error("no server hello") end
    rbuf = rbuf .. chunk
    records, rest = parse_records(rbuf)
  until #records > 0
  rbuf = rest

  local schedule = hs:process_server_hello(records[1].bytes)

  ---------------------------------------------------------
  local hs_transcript = hs.transcript:sdigest()
  --printh("REAL HS_TRANSCRIPT: " .. tohex(hs_transcript))
  ---------------------------------------------------------
  local enc = record.new(schedule.client_hs_key, schedule.client_hs_iv)
  local dec = record.new(schedule.server_hs_key, schedule.server_hs_iv)


  local rec_list = {}
  for i=2,#records do rec_list[#rec_list+1] = records[i] end

  local leftover = ""
  local server_finished
  local idx = 1
  while not server_finished do
    if idx > #rec_list then
      local chunk
      while sock:status() == 'ready' and not chunk do
        chunk = sock:read()
      end
      if not chunk then break end
      rbuf = rbuf .. chunk
      local more; more, rbuf = parse_records(rbuf)
      for _,v in ipairs(more) do rec_list[#rec_list+1] = v end
    end
    local r = rec_list[idx]; idx = idx + 1
    if not r then break end
    if r.type == constants.content_type.application_data then
      local pt, typ = dec:open(r.bytes)
      if pt and typ == constants.content_type.handshake then
        leftover = leftover .. pt
        while #leftover >= 4 do
          local len = (ord(leftover,2) << 16) | (ord(leftover,3) << 8) | ord(leftover,4)
          if #leftover < 4 + len then break end
          local msg = leftover:sub(1, 4 + len)
          local mtype = ord(leftover,1)
          if mtype == constants.handshake_type.finished then
            server_finished = msg
            leftover = leftover:sub(4 + len + 1)
            break
          else
            hs.transcript:update(msg)
            leftover = leftover:sub(4 + len + 1)
          end
        end
      end
    end
  end

  if not server_finished then error("server finished missing") end

  hs.transcript:update(server_finished)

-------------------------------------------------------------------
   local full_transcript = hs.transcript:sdigest()
   --printh("REAL FULL_TRANSCRIPT: " .. tohex(full_transcript))
-------------------------------------------------------------------

  leftover = ""

  if idx <= #rec_list then
    local remain = {}
    for i=idx,#rec_list do
      remain[#remain+1] = chr(rec_list[i].bytes:get())
    end
    rbuf = table.concat(remain) .. rbuf
  end

  schedule:derive_application(full_transcript)

  local verify = key_schedule.verify_data(schedule.client_hs_secret, full_transcript)
  local fin = chr(constants.handshake_type.finished) .. u24(#verify) .. verify
  hs.transcript:update(fin)
  local fin_record = enc:seal(constants.content_type.handshake, fin)
  sock:write(fin_record)
  local crandom = tohex(hs.client_random)
  local conn = setmetatable({
    _sock = sock,
    _enc = record.new(schedule.client_app_key, schedule.client_app_iv),
    _dec = record.new(schedule.server_app_key, schedule.server_app_iv),
    _rbuf = rbuf,
  }, Conn)
  return conn
end

return M
