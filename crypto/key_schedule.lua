--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

M.KEY_LEN = 32
M.IV_LEN = 12

local ZERO = string.rep("\0", hkdf.DIGEST_SIZE)

local function build_label(label, context, len)
  local full = "tls13 " .. label
  local t = { (len >> 8) & 0xff, len & 0xff, #full }
  for i=1,#full do
    t[#t+1] = ord(full, i)
  end
  t[#t+1] = #context
  for i=1,#context do
    t[#t+1] = ord(context, i)
  end
  return chr(table.unpack(t))
end

function M.hkdf_expand_label(secret, label, context, len)
  local info = build_label(label, context or "", len)
  return hkdf.expand(secret, info, len)
end

function M.derive_secret(secret, label, transcript_hash)
  return M.hkdf_expand_label(secret, label, transcript_hash or "", hkdf.DIGEST_SIZE)
end

function M.traffic_keys(secret)
  local key = M.hkdf_expand_label(secret, "key", "", M.KEY_LEN)
  local iv  = M.hkdf_expand_label(secret, "iv", "", M.IV_LEN)
  return key, iv
end

function M.finished_key(secret)
  return M.hkdf_expand_label(secret, "finished", "", hkdf.DIGEST_SIZE)
end

function M.verify_data(secret, hash)
  local key = M.finished_key(secret)
  local ctx = hmac.new(key)
  ctx:update(hash)
  local ud = ctx:udigest()
  return chr(ud:get(0, #ud))
end

function M.binder_key(psk, is_ext)
  local early = hkdf.extract(nil, psk)
  local label = is_ext and "ext binder" or "res binder"
  return M.derive_secret(early, label, "")
end

function M.new(shared_secret, psk)
  local self = {}

  if psk == nil or #psk == 0 then
    self.psk = ZERO
  else
    self.psk = psk
  end
  self.shared_secret = shared_secret or ""

  self.early_secret = hkdf.extract(nil, self.psk)
  local empty_hash = sha256.new():sdigest()
  local derived = M.derive_secret(self.early_secret, "derived", empty_hash)
  self.handshake_secret = hkdf.extract(derived, self.shared_secret)
  return setmetatable(self, { __index = M })
end

function M:derive_handshake(hash)
  self.client_hs_secret = M.derive_secret(self.handshake_secret, "c hs traffic", hash)
  self.server_hs_secret = M.derive_secret(self.handshake_secret, "s hs traffic", hash)
  self.client_hs_key, self.client_hs_iv = M.traffic_keys(self.client_hs_secret)
  self.server_hs_key, self.server_hs_iv = M.traffic_keys(self.server_hs_secret)
  local empty_hash = sha256.new():sdigest()
  local derived = M.derive_secret(self.handshake_secret, "derived", empty_hash)
  self.master_secret = hkdf.extract(derived, ZERO)
  return self.client_hs_key, self.client_hs_iv, self.server_hs_key, self.server_hs_iv
end

function M:derive_application(hash)
  assert(self.master_secret, "master secret not set")
  self.client_app_secret = M.derive_secret(self.master_secret, "c ap traffic", hash)
  self.server_app_secret = M.derive_secret(self.master_secret, "s ap traffic", hash)
  self.client_app_key, self.client_app_iv = M.traffic_keys(self.client_app_secret)
  self.server_app_key, self.server_app_iv = M.traffic_keys(self.server_app_secret)
  return self.client_app_key, self.client_app_iv, self.server_app_key, self.server_app_iv
end

return M
