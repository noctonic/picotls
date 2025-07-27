include("./crypto/crypto.lua")
print("._:Noctonic's PicoTLS v0.1:_.")

print("Creating TLS Connection")
local host = "noctonic.github.io"
local conn = tls.connect(host, 443)

print("Sending Request")
local req = table.concat({
  "GET /hello.txt HTTP/1.1\r\n",
  "Host: "..host.."\r\n",
  "Connection: close\r\n",
  "\r\n",
})

conn:write(req)

print("Reading Response")
local resp = conn:read()

local sep = "\r\n\r\n"
local header_end = resp:find(sep, 1, true)
local headers = resp:sub(1, header_end - 1)
local body = resp:sub(header_end + #sep)

--print("=== HEADERS ===")
--print(headers)
print("=== BODY ===")
print(body)
