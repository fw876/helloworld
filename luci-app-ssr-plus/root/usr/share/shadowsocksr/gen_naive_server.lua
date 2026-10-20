#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"
local s = assert(uci:get_all("shadowsocksr", arg[1]), "missing server section")
assert(s.username and s.username ~= "" and s.password and s.password ~= "", "Naive credentials required")
assert(s.tls_certificateFile and s.tls_keyFile, "Naive TLS certificate and key required")
local alpn = {}
local selected = s.naive_alpn or "h2"
assert(selected == "h2" or selected == "h3" or selected == "h2,h3", "invalid Naive transport")
for value in selected:gmatch("[^,]+") do alpn[#alpn + 1] = value end
print(json.stringify({
    log = {loglevel = "warning"},
    inbounds = {{listen = "::", port = assert(tonumber(s.server_port)), protocol = "naive",
        settings = {users = {{username = s.username, password = s.password}}},
        streamSettings = {network = "naive", security = "tls", tlsSettings = {
            alpn = alpn, certificates = {{certificateFile = s.tls_certificateFile, keyFile = s.tls_keyFile}}
        }}
    }},
    outbounds = {{protocol = "freedom", settings = {}}}
}, 1))
