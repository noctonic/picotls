--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

-- TLS record layer content types
M.content_type = {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
}

-- TLS handshake message types
M.handshake_type = {
  client_hello         = 1,
  server_hello         = 2,
  new_session_ticket   = 4,
  end_of_early_data    = 5,
  hello_retry_request  = 6,
  encrypted_extensions = 8,
  certificate          = 11,
  certificate_request  = 13,
  certificate_verify   = 15,
  finished             = 20,
  key_update           = 24,
  message_hash         = 254,
}

-- Alert levels
M.alert_level = {
  warning = 1,
  fatal   = 2,
}

-- Alert descriptions
M.alert_description = {
  close_notify = 0,
}

-- TLS protocol versions
M.version = {
  SSL3   = 0x0300,
  TLS1_0 = 0x0301,
  TLS1_1 = 0x0302,
  TLS1_2 = 0x0303,
  TLS1_3 = 0x0304,
}

-- Cipher suite
M.cipher_suite = {
  TLS_AES_128_GCM_SHA256       = 0x1301,
  TLS_AES_256_GCM_SHA384       = 0x1302,
  TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
  TLS_AES_128_CCM_SHA256       = 0x1304,
  TLS_AES_128_CCM_8_SHA256     = 0x1305,
}

-- Extension type
M.extension_type = {
  server_name               = 0,
  max_fragment_length       = 1,
  status_request            = 5,
  supported_groups          = 10,
  signature_algorithms      = 13,
  application_layer_protocol_negotiation = 16,
  record_size_limit         = 28,
  renegotiation_info        = 0xff01,
  pre_shared_key            = 41,
  early_data                = 42,
  supported_versions        = 43,
  cookie                    = 44,
  psk_key_exchange_modes    = 45,
  certificate_authorities   = 47,
  oid_filters               = 48,
  post_handshake_auth       = 49,
  signature_algorithms_cert = 50,
  key_share                 = 51,
}

-- Named group identifiers (supported_groups / key_share)
M.named_group = {
  secp256r1 = 23,
  secp384r1 = 24,
  secp521r1 = 25,
  x25519    = 29,
  x448      = 30,
  ffdhe2048 = 256,
}

-- Signature scheme identifiers
M.signature_scheme = {
  rsa_pkcs1_sha256         = 0x0401,
  rsa_pkcs1_sha384         = 0x0501,
  rsa_pkcs1_sha512         = 0x0601,
  ecdsa_secp256r1_sha256   = 0x0403,
  ecdsa_secp384r1_sha384   = 0x0503,
  ecdsa_secp521r1_sha512   = 0x0603,
  rsa_pss_rsae_sha256      = 0x0804,
  rsa_pss_rsae_sha384      = 0x0805,
  rsa_pss_rsae_sha512      = 0x0806,
  ed25519                  = 0x0807,
  ed448                    = 0x0808,
  rsa_pss_pss_sha256       = 0x0809,
  rsa_pss_pss_sha384       = 0x080A,
  rsa_pss_pss_sha512       = 0x080B,
}

-- PSK key exchange modes
M.psk_key_exchange_mode = {
  psk_ke = 0,
  psk_dhe_ke = 1,
}

return M
