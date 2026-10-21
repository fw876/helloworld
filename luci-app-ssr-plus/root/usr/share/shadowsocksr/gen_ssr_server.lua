#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"
local s = assert(uci:get_all("shadowsocksr", arg[1]), "missing server section")
print(json.stringify({
    log = {loglevel = "warning"},
    inbounds = {{listen = "::", port = assert(tonumber(s.server_port)), protocol = "shadowsocksr",
        settings = {password = assert(s.password), method = s.ssr_method or "aes-128-cfb",
            protocol = s.ssr_protocol or "auth_aes128_sha1", protocolParam = s.ssr_protocol_param or "",
            obfs = s.ssr_obfs or "plain", obfsParam = s.ssr_obfs_param or "", network = "tcp,udp"}
    }},
    outbounds = {{protocol = "freedom", settings = {}}}
}, 1))
