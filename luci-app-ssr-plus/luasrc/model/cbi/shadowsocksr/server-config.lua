-- Copyright (C) 2017 yushi studio <ywb94@qq.com>
-- Licensed to the public under the GNU General Public License v3.
require "luci.http"
require "luci.dispatcher"
require "nixio.fs"

local m, s, o
local sid = arg[1]

local encrypt_methods = {
	"rc4-md5",
	"rc4-md5-6",
	"rc4",
	"table",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"cast5-cfb",
	"des-cfb",
	"idea-cfb",
	"rc2-cfb",
	"seed-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf"
}

local encrypt_methods_ss = {
	-- aead
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
	-- aead 2022
	"2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305"
	--[[ stream
	"table",
	"rc4",
	"rc4-md5",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf" ]]
}

local protocol = {"origin"}

obfs = {"plain", "http_simple", "http_post"}

m = Map("shadowsocksr", translate("Edit ShadowSocksR Server"))

m.redirect = luci.dispatcher.build_url("admin/services/shadowsocksr/server")
if m.uci:get("shadowsocksr", sid) ~= "server_config" then
	luci.http.redirect(m.redirect)
	return
end

-- [[ Server Setting ]]--
s = m:section(NamedSection, sid, "server_config")
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.default = 1
o.rmempty = false

o = s:option(ListValue, "type", translate("Server Type"))
o:value("socks5", translate("Socks5"))
if nixio.fs.access("/usr/bin/ssserver") or nixio.fs.access("/usr/bin/ss-server") then
	o:value("ss", translate("Shadowsocks"))
end
if nixio.fs.access("/usr/bin/ssr-server") then
	o:value("ssr", translate("ShadowsocksR"))
end
o.default = "socks5"

o = s:option(Value, "server_port", translate("Server Port"))
o.datatype = "port"
math.randomseed(tostring(os.time()):reverse():sub(1, 7))
o.default = math.random(10240, 20480)
o.rmempty = false
o.description = translate("warning! Please do not reuse the port!")

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 60
o.rmempty = false
o:depends("type", "ss")
o:depends("type", "ssr")

o = s:option(Value, "username", translate("Username"))
o.rmempty = false
o:depends("type", "socks5")

o = s:option(Value, "password", translate("Password"))
o.password = true
o.rmempty = false

o = s:option(ListValue, "encrypt_method", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods) do
	o:value(v)
end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(ListValue, "encrypt_method_ss", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods_ss) do
	o:value(v)
end
o.rmempty = false
o:depends("type", "ss")

o = s:option(ListValue, "protocol", translate("Protocol"))
for _, v in ipairs(protocol) do
	o:value(v)
end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(ListValue, "obfs", translate("Obfs"))
for _, v in ipairs(obfs) do
	o:value(v)
end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(Value, "obfs_param", translate("Obfs param(optional)"))
o:depends("type", "ssr")

o = s:option(Flag, "fast_open", translate("TCP Fast Open"))
o.rmempty = false
o:depends("type", "ss")
o:depends("type", "ssr")

return m
