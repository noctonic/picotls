--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

local function u16(n)
  return chr((n >> 8) & 0xff, n & 0xff)
end

function M.supported_groups(groups)
  local t = {}
  for i, g in ipairs(groups) do t[#t+1] = u16(g) end
  local body = u16(#t * 2) .. table.concat(t)
  return u16(constants.extension_type.supported_groups) ..
         u16(#body) .. body
end

function M.key_share(group, pub)
  local share = u16(group) .. u16(#pub) .. pub
  local body  = u16(#share) .. share
  return u16(constants.extension_type.key_share) ..
         u16(#body) .. body
end

function M.signature_algorithms(algs)
  local t = {}
  for i, a in ipairs(algs) do t[#t+1] = u16(a) end
  local body = u16(#t * 2) .. table.concat(t)
  return u16(constants.extension_type.signature_algorithms) ..
         u16(#body) .. body
end

function M.supported_versions(versions)
  local t = {}
  for i, v in ipairs(versions) do t[#t+1] = u16(v) end
  local body = chr(#t * 2) .. table.concat(t)
  return u16(constants.extension_type.supported_versions) ..
         u16(#body) .. body
end

function M.server_name(hostname)
  local name = chr(0) .. u16(#hostname) .. hostname
  local list = u16(#name) .. name
  return u16(constants.extension_type.server_name) ..
         u16(#list) .. list
end

function M.psk_key_exchange_modes(modes)
  local t = {}
  for i, m in ipairs(modes) do t[#t+1] = chr(m) end
  local body = chr(#t) .. table.concat(t)
  return u16(constants.extension_type.psk_key_exchange_modes) ..
         u16(#body) .. body
end

function M.pre_shared_key(identity, binder_len)
  local id = u16(#identity) .. identity .. chr(0,0,0,0)
  local ids = u16(#id) .. id
  local binder = string.rep("\0", binder_len)
  local binders = u16(1 + binder_len) .. chr(#binder) .. binder
  local body = ids .. binders
  local ext = u16(constants.extension_type.pre_shared_key) ..
              u16(#body) .. body
  local offset = #ext - binder_len + 1
  return ext, offset
end

function M.alpn(protocols)
  local t = {}
  for i, p in ipairs(protocols) do
    t[#t+1] = chr(#p) .. p
  end
  local list = table.concat(t)
  local body = u16(#list) .. list
  return u16(constants.extension_type.application_layer_protocol_negotiation) ..
         u16(#body) .. body
end

return M
