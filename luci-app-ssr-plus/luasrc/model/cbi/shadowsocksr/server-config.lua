-- Copyright (C) 2017 yushi studio <ywb94@qq.com>
-- Licensed to the public under the GNU General Public License v3.
require "luci.http"
require "luci.dispatcher"
require "nixio.fs"

local m, s, o
local sid = arg[1]

-- 加密方式（SS/SSR用）
local encrypt_methods = {
	"rc4-md5", "rc4-md5-6", "rc4", "table",
	"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
	"bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
	"cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
	"salsa20", "chacha20", "chacha20-ietf"
}

local encrypt_methods_ss = {
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
	"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

-- Shadowsocks 加密方法（Xray 版）
local v_ss_encrypt_method_list = {
	"aes-128-cfb", "aes-256-cfb", "aes-128-gcm", "aes-256-gcm",
	"chacha20", "chacha20-ietf", "chacha20-poly1305", "chacha20-ietf-poly1305"
}

-- 伪装类型（用于 mKCP/QUIC）
local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
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

-- ========== 基本设置 ==========
o = s:option(Flag, "enable", translate("Enable"))
o.default = 1
o.rmempty = false

o = s:option(ListValue, "type", translate("Server Type"))
o:value("socks5", translate("Socks5"))
if nixio.fs.access("/usr/bin/mihomo") or nixio.fs.access("/usr/libexec/mihomo") or nixio.fs.access("/usr/bin/ssserver") or nixio.fs.access("/usr/libexec/ssserver") then
	o:value("ss", translate("ShadowSocks"))
end
if nixio.fs.access("/usr/bin/ssr-server") then
	o:value("ssr", translate("ShadowsocksR"))
end
-- Xray 协议支持
if nixio.fs.access("/usr/bin/mihomo") or nixio.fs.access("/usr/libexec/mihomo")
	or nixio.fs.access("/usr/bin/xray") or nixio.fs.access("/usr/libexec/xray")
then
	o:value("vmess", "VMess (Mihomo/Xray)")
	o:value("vless", "VLESS (Mihomo/Xray)")
	o:value("trojan", "Trojan (Mihomo/Xray)")
	o:value("shadowsocks", "Shadowsocks (Mihomo/Xray)")
end
if nixio.fs.access("/usr/bin/xray") or nixio.fs.access("/usr/libexec/xray") then
	o:value("naive", "NaiveProxy (Xray)")
	o:value("tuic", "TUIC (Xray)")
	o:value("snell", "Snell (Xray)")
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
o:depends("type", "naive")

o = s:option(Value, "password", translate("Password"))
o.password = true
o.rmempty = false
o:depends("type", "socks5")
o:depends("type", "naive")
o:depends("type", "ss")
o:depends("type", "ssr")
o:depends("type", "trojan")
o:depends("type", "shadowsocks")

-- ========== SS/SSR 协议特有 ==========
o = s:option(ListValue, "encrypt_method", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods) do o:value(v) end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(ListValue, "encrypt_method_ss", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods_ss) do o:value(v) end
o.rmempty = false
o:depends("type", "ss")

o = s:option(ListValue, "protocol", translate("Protocol"))
for _, v in ipairs(protocol) do o:value(v) end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(ListValue, "obfs", translate("Obfs"))
for _, v in ipairs(obfs) do o:value(v) end
o.rmempty = false
o:depends("type", "ssr")

o = s:option(Value, "obfs_param", translate("Obfs param (optional)"))
o:depends("type", "ssr")

o = s:option(Flag, "fast_open", translate("TCP Fast Open"))
o.rmempty = false
o:depends("type", "ss")
o:depends("type", "ssr")

-- ========== Xray 协议通用字段 ==========
-- 用户备注
o = s:option(Value, "remarks", translate("Remarks"))
o.default = translate("Remarks")
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")
o:depends("type", "shadowsocks")

-- 用户等级
o = s:option(Value, "level", translate("User Level"))
o.datatype = "uinteger"
o.default = 1
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "shadowsocks")
o:depends("type", "trojan")

-- ========== Xray 协议认证字段 ==========
-- UUID (用于 vmess/vless)
o = s:option(Value, "uuid", translate("UUID"))
o.description = translate("Required for VMess/VLESS. Generate with: uuidgen")
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")

-- Trojan 密码
o = s:option(Value, "trojan_password", translate("Trojan Password"))
o.password = true
o.rmempty = true
o:depends("type", "trojan")

-- Shadowsocks 密码和加密（Xray 内置）
o = s:option(Value, "ss_password", translate("Shadowsocks Password"))
o.password = true
o.rmempty = true
o:depends("type", "shadowsocks")

o = s:option(ListValue, "ss_method", translate("Encrypt Method"))
for _, v in ipairs(v_ss_encrypt_method_list) do o:value(v) end
o.default = "chacha20-ietf-poly1305"
o.rmempty = true
o:depends("type", "shadowsocks")

o = s:option(ListValue, "ss_network", translate("Transport"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o.default = "tcp,udp"
o.rmempty = true
o:depends("type", "shadowsocks")

-- VMess alterId
o = s:option(Value, "alter_id", translate("Alter ID"))
o.datatype = "uinteger"
o.default = 0
o.rmempty = true
o:depends("type", "vmess")

-- VLESS decryption
o = s:option(Value, "decryption", translate("Decryption"))
o.default = "none"
o.rmempty = true
o:depends("type", "vless")

-- ========== TLS / XTLS 设置 ==========
o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")
o:depends("type", "shadowsocks")

o = s:option(Flag, "xtls", translate("XTLS"))
o.default = 0
o.rmempty = true
o:depends({ type = "vless", tls = "1" })

o = s:option(ListValue, "flow", translate("Flow"))
o:value("xtls-rprx-origin", "xtls-rprx-origin")
o:value("xtls-rprx-origin-udp443", "xtls-rprx-origin-udp443")
o:value("xtls-rprx-direct", "xtls-rprx-direct")
o:value("xtls-rprx-direct-udp443", "xtls-rprx-direct-udp443")
o:value("xtls-rprx-splice", "xtls-rprx-splice")
o:value("xtls-rprx-splice-udp443", "xtls-rprx-splice-udp443")
o.default = "xtls-rprx-direct"
o.rmempty = true
o:depends("xtls", "1")

o = s:option(Value, "tls_serverName", translate("Server Name (SNI)"))
o.rmempty = true
o:depends("tls", "1")

o = s:option(Value, "tls_certificateFile", translate("Certificate File Path"))
o.description = translate("e.g.: /etc/ssl/fullchain.pem")
o.rmempty = true
o:depends("tls", "1")
o:depends("type", "tuic")

o:depends("type", "naive")

o = s:option(Value, "tls_keyFile", translate("Private Key File Path"))
o.description = translate("e.g.: /etc/ssl/private.key")
o.rmempty = true
o:depends("tls", "1")
o:depends("type", "tuic")

-- ========== 传输层设置 (Transport) ==========
o:depends("type", "naive")

o = s:option(ListValue, "transport", translate("Transport Protocol"))
o:value("tcp", "TCP")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("h2", "HTTP/2")
o:value("ds", "DomainSocket")
o:value("quic", "QUIC")
o.default = "tcp"
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")

-- ----- WebSocket 设置 -----
o = s:option(Value, "ws_host", translate("WebSocket Host"))
o.rmempty = true
o:depends("transport", "ws")
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")

o = s:option(Value, "ws_path", translate("WebSocket Path"))
o.default = "/"
o.rmempty = true
o:depends("transport", "ws")
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")

-- ----- HTTP/2 设置 -----
o = s:option(Value, "h2_host", translate("HTTP/2 Host"))
o.rmempty = true
o:depends("transport", "h2")
o:depends("type", "vmess")
o:depends("type", "vless")

o = s:option(Value, "h2_path", translate("HTTP/2 Path"))
o.default = "/"
o.rmempty = true
o:depends("transport", "h2")
o:depends("type", "vmess")
o:depends("type", "vless")

-- ----- TCP 伪装设置 -----
o = s:option(ListValue, "tcp_guise", translate("TCP Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o.default = "none"
o.rmempty = true
o:depends("transport", "tcp")
o:depends("type", "vmess")
o:depends("type", "vless")

o = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
o.rmempty = true
o:depends("tcp_guise", "http")

o = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
o.rmempty = true
o:depends("tcp_guise", "http")

-- ----- mKCP 设置 -----
o = s:option(ListValue, "mkcp_guise", translate("mKCP Camouflage Type"))
for _, v in ipairs(header_type_list) do o:value(v) end
o.default = "none"
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_mtu", translate("KCP MTU"))
o.datatype = "uinteger"
o.default = 1350
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_tti", translate("KCP TTI"))
o.datatype = "uinteger"
o.default = 20
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_uplinkCapacity", translate("KCP Uplink Capacity"))
o.datatype = "uinteger"
o.default = 5
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_downlinkCapacity", translate("KCP Downlink Capacity"))
o.datatype = "uinteger"
o.default = 20
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Flag, "mkcp_congestion", translate("KCP Congestion Control"))
o.default = 0
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_readBufferSize", translate("KCP Read Buffer Size"))
o.datatype = "uinteger"
o.default = 1
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_writeBufferSize", translate("KCP Write Buffer Size"))
o.datatype = "uinteger"
o.default = 1
o.rmempty = true
o:depends("transport", "mkcp")

o = s:option(Value, "mkcp_seed", translate("KCP Seed"))
o.datatype = "uinteger"
o.rmempty = true
o:depends("transport", "mkcp")

-- ----- DomainSocket 设置 -----
o = s:option(Value, "ds_path", translate("DomainSocket Path"))
o.description = translate("A legal file path. This file must not exist before running.")
o.rmempty = true
o:depends("transport", "ds")

-- ----- QUIC 设置 -----
o = s:option(ListValue, "quic_security", translate("QUIC Security"))
o:value("none", "none")
o:value("aes-128-gcm", "aes-128-gcm")
o:value("chacha20-poly1305", "chacha20-poly1305")
o.default = "none"
o.rmempty = true
o:depends("transport", "quic")

o = s:option(Value, "quic_key", translate("QUIC Key"))
o.rmempty = true
o:depends("transport", "quic")

o = s:option(ListValue, "quic_guise", translate("QUIC Camouflage Type"))
for _, v in ipairs(header_type_list) do o:value(v) end
o.default = "none"
o.rmempty = true
o:depends("transport", "quic")

-- ========== 访问控制 ==========
o = s:option(Flag, "bind_local", translate("Bind Local Only"))
o.description = translate("When selected, it can only be accessed locally. Recommended when using reverse proxies.")
o.default = 0
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")
o:depends("type", "shadowsocks")

o = s:option(Flag, "accept_lan", translate("Accept LAN Access"))
o.description = translate("When selected, it can be accessed from LAN. This may not be safe!")
o.default = 0
o.rmempty = true
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "trojan")
o:depends("type", "shadowsocks")

o = s:option(ListValue, "naive_alpn", translate("Naive transport"))
o:value("h2", "HTTP/2")
o:value("h3", "HTTP/3")
o:value("h2,h3", "HTTP/2 + HTTP/3")
o.default = "h2"
o:depends("type", "naive")

-- TUIC credentials are independent of the legacy server settings.
for _, field in ipairs({{"tuic_uuid", "TUIC UUID"}, {"tuic_password", "TUIC Password"}, {"tuic_token", "TUIC v4 Token"}}) do
	o = s:option(Value, field[1], field[2])
	o.password = field[1] ~= "tuic_uuid"
	o:depends("type", "tuic")
end

o = s:option(Value, "snell_psk", translate("Snell PSK"))
o.password = true
o:depends("type", "snell")
o = s:option(ListValue, "snell_version", translate("Snell Version"))
for _, version in ipairs({"1", "2", "3", "4", "5"}) do o:value(version, "v" .. version) end
o.default = "4"
o:depends("type", "snell")
o = s:option(ListValue, "snell_obfs", translate("Snell Obfs"))
o:value("", translate("Disable"))
o:value("http", "HTTP")
o:value("tls", "TLS")
o:depends("type", "snell")
o = s:option(Flag, "snell_udp", translate("UDP Relay"))
o.default = "1"
for _, version in ipairs({"3", "4", "5"}) do
	o:depends({type = "snell", snell_version = version})
end

return m
