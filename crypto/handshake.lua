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
    error("[handshake]: expected string or userdata")
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

local function ud_to_str(u)
  return chr(u:get(0, #u))
end
local function u16(n)
  return chr((n >> 8) & 0xff, n & 0xff)
end

local function u24(n)
  return chr((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
end

local function parse_u8(buf, pos)
  return buf:get(pos), pos + 1
end

local function parse_u16(buf, pos)
  local hi = buf:get(pos)
  local lo = buf:get(pos + 1)
  return (hi << 8) | lo, pos + 2
end

local function parse_u24(buf, pos)
  local b1 = buf:get(pos)
  local b2 = buf:get(pos + 1)
  local b3 = buf:get(pos + 2)
  return (b1 << 16) | (b2 << 8) | b3, pos + 3
end

local function ext_supported_versions(versions)
  return extensions.supported_versions(versions)
end

local function ext_server_name(host)
  if not host then return "" end
  return extensions.server_name(host)
end

function M.new(opts)
  opts = opts or {}
  local self = {}
  
  self.cipher_suites = {
    
    constants.cipher_suite.TLS_CHACHA20_POLY1305_SHA256,
    
  }
  self.supported_groups = opts.supported_groups or {
    constants.named_group.x25519,
  }
  self.signature_algorithms = opts.signature_algorithms or {
    constants.signature_scheme.rsa_pss_rsae_sha256,
    constants.signature_scheme.rsa_pkcs1_sha256,
    constants.signature_scheme.ed25519,
    constants.signature_scheme.ed448,
  }
  self.supported_versions = opts.supported_versions or {
    constants.version.TLS1_3,
  }
  self.compatibility_mode = opts.compatibility_mode ~= false
  self.psk = opts.psk
  self.alpn = opts.alpn
  if opts.client_random then
    self.client_random = to_udata(opts.client_random)
  else
    self.client_random = rng.udata(32)
  end

  if opts.private_key then
    self._priv = to_udata(opts.private_key)
  else
    self._priv = rng.udata(32)
  end

  self._pub = to_udata(x25519.scalar_base_mult(ud_to_str(self._priv)))
  self.client_pub = self._pub
  self.transcript = sha256.new()
  return setmetatable(self, {__index=M})
end

function M:client_hello(host)
  local suites = {}
  for i=1,#self.cipher_suites do
    suites[#suites+1] = u16(self.cipher_suites[i])
  end
  local suite_bytes = table.concat(suites)

  
  local exts = {}
  if self.compatibility_mode then
    exts[#exts+1] = {
      constants.extension_type.renegotiation_info,
      u16(constants.extension_type.renegotiation_info) .. u16(1) .. chr(0)
    }
  end
  exts[#exts+1] = {constants.extension_type.server_name,
                   ext_server_name(host)}
  exts[#exts+1] = {constants.extension_type.supported_groups,
                   extensions.supported_groups(self.supported_groups)}
  exts[#exts+1] = {constants.extension_type.signature_algorithms,
                   extensions.signature_algorithms(self.signature_algorithms)}
  exts[#exts+1] = {constants.extension_type.supported_versions,
                   ext_supported_versions(self.supported_versions)}
  if self.alpn then
    exts[#exts+1] = {constants.extension_type.application_layer_protocol_negotiation,
                     extensions.alpn(self.alpn)}
  end
  exts[#exts+1] = {constants.extension_type.key_share,
                   extensions.key_share(self.supported_groups[1], ud_to_str(self._pub))}
  local binder_offset
  if self.psk then
    exts[#exts+1] = {
      constants.extension_type.psk_key_exchange_modes,
      extensions.psk_key_exchange_modes{
        constants.psk_key_exchange_mode.psk_dhe_ke,
      }
    }
    local psk_ext, off = extensions.pre_shared_key(
      "Client_identity",
      sha256.DIGEST_SIZE
    )
    exts[#exts+1] = {constants.extension_type.pre_shared_key, psk_ext, off}
  end

  local order = {
    constants.extension_type.supported_versions,
    constants.extension_type.supported_groups,
    constants.extension_type.key_share,
    constants.extension_type.signature_algorithms,
  }
  local map = {}
  for _, e in ipairs(exts) do
    map[e[1]] = e
  end
  local ext_parts = {}
  local off = 0
  for _, typ in ipairs(order) do
    local e = map[typ]
    if e then
      ext_parts[#ext_parts+1] = e[2]
      if typ == constants.extension_type.pre_shared_key then
        binder_offset = off + (e[3] or 0)
      end
      off = off + #e[2]
    end
  end
  local ext_body = table.concat(ext_parts)
  local body_parts = {}
  body_parts[#body_parts+1] = u16(constants.version.TLS1_2)
  body_parts[#body_parts+1] = ud_to_str(self.client_random)
  if self.compatibility_mode then
    self.session_id = rng.udata(32)
    body_parts[#body_parts+1] = chr(32) .. ud_to_str(self.session_id)
  else
    self.session_id = ""
    body_parts[#body_parts+1] = chr(0)
  end
  body_parts[#body_parts+1] = u16(#suite_bytes)
  body_parts[#body_parts+1] = suite_bytes
  body_parts[#body_parts+1] = chr(1) .. chr(0) 
  local body_prefix = table.concat(body_parts)
  local body = body_prefix .. u16(#ext_body) .. ext_body

  local msg = chr(constants.handshake_type.client_hello) ..
              u24(#body) .. body
  if self.psk then
    local binder_start = 4 + #body_prefix + 2 + (binder_offset or 0)
    local thash = sha256.new(msg):sdigest()
    local bkey = key_schedule.binder_key(self.psk, true)
    local binder = key_schedule.verify_data(bkey, thash)
    msg = msg:sub(1, binder_start-1) .. binder .. msg:sub(binder_start + sha256.DIGEST_SIZE)
  end
  self.transcript:update(msg)
  
  return msg
end

local function parse_extensions(self, buf)
  buf = to_udata(buf)
  local pos = 0
  while pos < #buf do
    local typ; typ, pos = parse_u16(buf, pos)
    local len; len, pos = parse_u16(buf, pos)
    if typ == constants.extension_type.key_share then
      local grp; grp, tmp = parse_u16(buf, pos)
      local slen; slen, tmp = parse_u16(buf, pos + 2)
      local share_ud = userdata("u8", slen)
      share_ud:set(0, buf:get(pos + 4, slen))
      self.server_group = grp
      self.server_pub = share_ud
    elseif typ == constants.extension_type.supported_versions then
      local ver; ver, _ = parse_u16(buf, pos)
      self.negotiated_version = ver
    elseif typ == constants.extension_type.pre_shared_key then
      local idx; idx, _ = parse_u16(buf, pos)
      self.psk_index = idx
    end
    pos = pos + len
  end
end

function M:process_server_hello(msg)
  msg = to_udata(msg)
  local pos = 0
  
  if msg:get(0) == constants.content_type.handshake then
    
    assert(#msg >= 5, "record too short")
    local len = (msg:get(3) << 8) | msg:get(4)
    assert(#msg >= 5 + len, "record length mismatch")
    local tmp = userdata("u8", len)
    tmp:set(0, msg:get(5, len))
    msg = tmp
  end

  
  local hlen; hlen, pos = parse_u24(msg, 1)
  if #msg > 4 + hlen then
    local tmp = userdata("u8", 4 + hlen)
    tmp:set(0, msg:get(0, 4 + hlen))
    msg = tmp
  end

  local typ = msg:get(0)
  assert(typ == constants.handshake_type.server_hello,
         "unexpected handshake message")
  local len; len, pos = parse_u24(msg, 1)
  assert(#msg == 4 + len, "handshake length mismatch")
  local body = userdata("u8", len)
  body:set(0, msg:get(4, len))
  self.transcript:update(msg)
  

  pos = 0
  local ver; ver, pos = parse_u16(body, pos)
  local rand = userdata("u8", 32)
  rand:set(0, body:get(pos, 32))
  self.server_random = rand
  pos = pos + 32
  local sid_len; sid_len, pos = parse_u8(body, pos)
  pos = pos + sid_len 
  self.cipher_suite, pos = parse_u16(body, pos)
  
  pos = pos + 1 
  local ext_len; ext_len, pos = parse_u16(body, pos)
  local ext_ud = userdata("u8", ext_len)
  ext_ud:set(0, body:get(pos, ext_len))
  parse_extensions(self, ext_ud)
  
  assert(self.server_group == self.supported_groups[1],
         "unsupported key share group")
  local shared = x25519.scalar_mult(ud_to_str(self._priv), ud_to_str(self.server_pub))
  self.schedule = key_schedule.new(shared, self.psk)
  
  local thash = self.transcript:sdigest()
  
  self.schedule:derive_handshake(thash)
  return self.schedule
end

return M

