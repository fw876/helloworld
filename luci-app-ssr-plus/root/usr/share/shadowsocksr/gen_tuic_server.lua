#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"
local s = assert(uci:get_all("shadowsocksr", arg[1]), "missing server section")
local users, tokens = {}, {}
if s.tuic_uuid and s.tuic_uuid ~= "" then
    users[s.tuic_uuid] = assert(s.tuic_password, "TUIC password required")
end
if s.tuic_token and s.tuic_token ~= "" then tokens[1] = s.tuic_token end
assert(next(users) or #tokens > 0, "TUIC credentials required")
print(json.stringify({
    log = {loglevel = "warning"},
    inbounds = {{listen = "::", port = assert(tonumber(s.server_port)), protocol = "tuic",
        settings = {users = next(users) and users or nil, tokens = #tokens > 0 and tokens or nil,
            certificateFile = assert(s.tls_certificateFile), keyFile = assert(s.tls_keyFile)},
        streamSettings = {network = "tuic"}
    }},
    outbounds = {{protocol = "freedom", settings = {}}}
}, 1))
