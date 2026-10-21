#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"
local s = assert(uci:get_all("shadowsocksr", arg[1]), "missing server section")
local padding = {}
for line in (s.anytls_padding or ""):gmatch("[^\r\n]+") do padding[#padding + 1] = line end
print(json.stringify({
    log = {loglevel = "warning"},
    inbounds = {{listen = "::", port = assert(tonumber(s.server_port)), protocol = "anytls",
        settings = {users = {{email = "user", password = assert(s.anytls_password)}},
            paddingScheme = #padding > 0 and padding or nil},
        streamSettings = {network = "raw", security = "tls", tlsSettings = {
            certificates = {{oneTimeLoading = true, certificateFile = assert(s.tls_certificateFile), keyFile = assert(s.tls_keyFile)}}
        }}
    }},
    outbounds = {{protocol = "freedom", settings = {}}}
}, 1))
