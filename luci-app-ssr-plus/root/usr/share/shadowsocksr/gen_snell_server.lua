#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"
local s = assert(uci:get_all("shadowsocksr", arg[1]), "missing server section")
local version = tonumber(s.snell_version) or 4
print(json.stringify({
    log = {loglevel = "warning"},
    inbounds = {{listen = "::", port = assert(tonumber(s.server_port)), protocol = "snell",
        settings = {psk = assert(s.snell_psk), version = version,
            obfs = s.snell_obfs or "", udp = version >= 3 and s.snell_udp ~= "0"}
    }},
    outbounds = {{protocol = "freedom", settings = {}}}
}, 1))
