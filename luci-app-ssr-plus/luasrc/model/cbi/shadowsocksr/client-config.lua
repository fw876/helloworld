-- Copyright (C) 2017 yushi studio <ywb94@qq.com> github.com/ywb94
-- Licensed to the public under the GNU General Public License v3.

require "nixio.fs"
require "luci.sys"
require "luci.http"
require "luci.jsonc"
require "luci.model.ipkg"
require "luci.model.uci"
local uci = require "luci.model.uci".cursor()

local m, s, o

local sid = arg[1]
local uuid = luci.sys.exec("cat /proc/sys/kernel/random/uuid")

-- 确保正确判断程序是否存在
local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" 2>/dev/null', e)) ~= ""
end

local function is_installed(e)
	return luci.model.ipkg.installed(e)
end

local has_ss_rust = is_finded("sslocal") or is_finded("ssserver")
local has_ss_libev = is_finded("ss-redir") or is_finded("ss-local")

-- 读取当前存储的 ss_type
local ss_type = uci:get_first("shadowsocksr", "server_subscribe", "ss_type")

local server_table = {}
local encrypt_methods = {
	-- ssr
	"none",
	"table",
	"rc4",
	"rc4-md5-6",
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
	-- plain
	"none",
	"plain",
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
	"none",
	"plain",
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
	"chacha20-ietf" ]]--
}

local protocol = {
	-- ssr
	"origin",
	"verify_deflate",
	"auth_sha1_v4",
	"auth_aes128_sha1",
	"auth_aes128_md5",
	"auth_chain_a",
	"auth_chain_b",
	"auth_chain_c",
	"auth_chain_d",
	"auth_chain_e",
	"auth_chain_f"
}

local obfs = {
	-- ssr
	"plain",
	"http_simple",
	"http_post",
	"random_head",
	"tls1.2_ticket_auth"
}

local securitys = {
	-- vmess
	"auto",
	"none",
	"zero",
	"aes-128-gcm",
	"chacha20-poly1305"
}

local tls_flows = {
	-- tls
	"xtls-rprx-vision",
	"xtls-rprx-vision-udp443",
	"none"
}

m = Map("shadowsocksr", translate("Edit ShadowSocksR Server"))
m.redirect = luci.dispatcher.build_url("admin/services/shadowsocksr/servers")
if m.uci:get("shadowsocksr", sid) ~= "servers" then
	luci.http.redirect(m.redirect)
	return
end

-- [[ Servers Setting ]]--
s = m:section(NamedSection, sid, "servers")
s.anonymous = true
s.addremove = false

o = s:option(DummyValue, "ssr_url", "SS/SSR/V2RAY/TROJAN/HYSTERIA2 URL")
o.rawhtml = true
o.template = "shadowsocksr/ssrurl"
o.value = sid

o = s:option(ListValue, "type", translate("Server Node Type"))
if is_finded("xray") or is_finded("v2ray") then
	o:value("v2ray", translate("V2Ray/XRay"))
end
if is_finded("ssr-redir") then
	o:value("ssr", translate("ShadowsocksR"))
end
if has_ss_rust or has_ss_libev then
    o:value("ss", translate("ShadowSocks"))
end
if is_finded("trojan") then
	o:value("trojan", translate("Trojan"))
end
if is_finded("naive") then
	o:value("naiveproxy", translate("NaiveProxy"))
end
if is_finded("hysteria") then
	o:value("hysteria2", translate("Hysteria2"))
end
if is_finded("tuic-client") then
	o:value("tuic", translate("TUIC"))
end
if is_finded("shadow-tls") and is_finded("sslocal") then
	o:value("shadowtls", translate("Shadow-TLS"))
end
if is_finded("ipt2socks") then
	o:value("socks5", translate("Socks5"))
end
if is_finded("redsocks2") then
	o:value("tun", translate("Network Tunnel"))
end

o.description = translate("Using incorrect encryption mothod may causes service fail to start")

o = s:option(Value, "alias", translate("Alias(optional)"))

o = s:option(ListValue, "iface", translate("Network interface to use"))
for _, e in ipairs(luci.sys.net.devices()) do
	if e ~= "lo" then
		o:value(e)
	end
end
o:depends("type", "tun")
o.description = translate("Redirect traffic to this network interface")

-- 新增一个选择框，用于选择 Shadowsocks 版本
o = s:option(ListValue, "has_ss_type", string.format("<b><span style='color:red;'>%s</span></b>", translate("ShadowSocks Node Use Version")))
o.description = translate("Selection ShadowSocks Node Use Version.")
-- 设置默认 Shadowsocks 版本
-- 动态添加选项
if has_ss_rust then
    o:value("ss-rust", translate("ShadowSocks-rust Version"))
end
if has_ss_libev then
    o:value("ss-libev", translate("ShadowSocks-libev Version"))
end
-- 设置默认值
if ss_type == "ss-rust" then
    o.default = "ss-rust"
elseif ss_type == "ss-libev" then
    o.default = "ss-libev"
end
o:depends("type", "ss")
o.write = function(self, section, value)
    -- 更新 Shadowsocks 节点的 has_ss_type
    uci:foreach("shadowsocksr", "servers", function(s)
        local node_type = uci:get("shadowsocksr", s[".name"], "type")  -- 获取节点类型
        if node_type == "ss" then  -- 仅修改 Shadowsocks 节点
            local old_value = uci:get("shadowsocksr", s[".name"], "has_ss_type")
            if old_value ~= value then
                uci:set("shadowsocksr", s[".name"], "has_ss_type", value)
            end
        end
    end)

    -- 更新 server_subscribe 的 ss_type
    local old_value = uci:get("shadowsocksr", "server_subscribe", "ss_type")
    if old_value ~= value then
        uci:set("shadowsocksr", "@server_subscribe[0]", "ss_type", value)
    end

    -- 更新当前 section 的 has_ss_type
    Value.write(self, section, value)
end

o = s:option(ListValue, "v2ray_protocol", translate("V2Ray/XRay protocol"))
o:value("vless", translate("VLESS"))
o:value("vmess", translate("VMess"))
o:value("trojan", translate("Trojan"))
o:value("shadowsocks", translate("ShadowSocks"))
if is_finded("xray") then
	o:value("wireguard", translate("WireGuard"))
end
o:value("socks", translate("Socks"))
o:value("http", translate("HTTP"))
o:depends("type", "v2ray")

o = s:option(Value, "server", translate("Server Address"))
o.datatype = "host"
o.rmempty = false
o:depends("type", "ssr")
o:depends("type", "ss")
o:depends("type", "v2ray")
o:depends("type", "trojan")
o:depends("type", "naiveproxy")
o:depends("type", "hysteria2")
o:depends("type", "tuic")
o:depends("type", "shadowtls")
o:depends("type", "socks5")

o = s:option(Value, "server_port", translate("Server Port"))
o.datatype = "port"
o.rmempty = true
o:depends("type", "ssr")
o:depends("type", "ss")
o:depends("type", "v2ray")
o:depends("type", "trojan")
o:depends("type", "naiveproxy")
o:depends("type", "hysteria2")
o:depends("type", "tuic")
o:depends("type", "shadowtls")
o:depends("type", "socks5")

o = s:option(Flag, "auth_enable", translate("Enable Authentication"))
o.rmempty = false
o.default = "0"
o:depends("type", "socks5")
o:depends({type = "v2ray", v2ray_protocol = "http"})
o:depends({type = "v2ray", v2ray_protocol = "socks"})

o = s:option(Value, "username", translate("Username"))
o.rmempty = true
o:depends("type", "naiveproxy")
o:depends({type = "socks5", auth_enable = true})
o:depends({type = "v2ray", v2ray_protocol = "http", auth_enable = true})
o:depends({type = "v2ray", v2ray_protocol = "socks", auth_enable = true})

o = s:option(Value, "password", translate("Password"))
o.password = true
o.rmempty = true
o:depends("type", "ssr")
o:depends("type", "ss")
o:depends("type", "trojan")
o:depends("type", "naiveproxy")
o:depends("type", "shadowtls")
o:depends({type = "socks5", auth_enable = true})
o:depends({type = "v2ray", v2ray_protocol = "http", auth_enable = true})
o:depends({type = "v2ray", v2ray_protocol = "socks", socks_ver = "5", auth_enable = true})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o:depends({type = "v2ray", v2ray_protocol = "trojan"})

o = s:option(ListValue, "encrypt_method", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods) do
	o:value(v)
end
o.rmempty = true
o:depends("type", "ssr")

o = s:option(ListValue, "encrypt_method_ss", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods_ss) do
	if v == "none" then
	   o.default = "none"
	   o:value("none", translate("none"))
	else
	    o:value(v, translate(v))
	end
end
o.rmempty = true
o:depends("type", "ss")
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})

o = s:option(Flag, "uot", translate("UDP over TCP"))
o.description = translate("Enable the SUoT protocol, requires server support.")
o.rmempty = true
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o.default = "0"

o = s:option(Flag, "ivCheck", translate("Bloom Filter"))
o.rmempty = true
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o.default = "1"

-- [[ Enable Shadowsocks Plugin ]]--
o = s:option(Flag, "enable_plugin", translate("Enable Plugin"))
o.rmempty = true
o:depends("type", "ss")
o.default = "0"

-- Shadowsocks Plugin
o = s:option(ListValue, "plugin", translate("Obfs"))
o:value("none", translate("None"))
if is_finded("obfs-local") then
	o:value("obfs-local", translate("obfs-local"))
end
if is_finded("v2ray-plugin") then
	o:value("v2ray-plugin", translate("v2ray-plugin"))
end
if is_finded("xray-plugin") then
	o:value("xray-plugin", translate("xray-plugin"))
end
o:value("custom", translate("Custom"))
o.rmempty = true
o:depends({enable_plugin = true})

o = s:option(Value, "custom_plugin", translate("Custom Plugin Path"))
o.placeholder = "/path/to/custom-plugin"
o:depends({plugin = "custom"})

o = s:option(Value, "plugin_opts", translate("Plugin Opts"))
o.rmempty = true
o:depends({enable_plugin = true})

o = s:option(ListValue, "protocol", translate("Protocol"))
for _, v in ipairs(protocol) do
	o:value(v)
end
o.rmempty = true
o:depends("type", "ssr")

o = s:option(Value, "protocol_param", translate("Protocol param (optional)"))
o:depends("type", "ssr")

o = s:option(ListValue, "obfs", translate("Obfs"))
for _, v in ipairs(obfs) do
	o:value(v)
end
o.rmempty = true
o:depends("type", "ssr")

o = s:option(Value, "obfs_param", translate("Obfs param (optional)"))
o:depends("type", "ssr")


-- [[ Hysteria2 ]]--
o = s:option(Value, "hy2_auth", translate("Users Authentication"))
o:depends("type", "hysteria2")
o.rmempty = false

o = s:option(Flag, "flag_port_hopping", translate("Enable Port Hopping"))
o:depends("type", "hysteria2")
o.rmempty = true
o.default = "0"

o = s:option(Value, "port_range", translate("Port hopping range"))
o.description = translate("Format as 10000:20000 or 10000-20000 Multiple groups are separated by commas (,).")
o:depends({type = "hysteria2", flag_port_hopping = true})
--o.datatype = "portrange"
o.rmempty = true

o = s:option(Flag, "flag_transport", translate("Enable Transport Protocol Settings"))
o:depends("type", "hysteria2")
o.rmempty = true
o.default = "0"

o = s:option(ListValue, "transport_protocol", translate("Transport Protocol"))
o:depends({type = "hysteria2", flag_transport = true})
o:value("udp", translate("UDP"))
o.default = "udp"
o.rmempty = true

o = s:option(Value, "hopinterval", translate("Port Hopping Interval(Unit:Second)"))
o:depends({type = "hysteria2", flag_transport = true, flag_port_hopping = true})
o.datatype = "uinteger"
o.rmempty = true
o.default = "30"

o = s:option(Flag, "flag_obfs", translate("Enable Obfuscation"))
o:depends("type", "hysteria2")
o.rmempty = true
o.default = "0"

o = s:option(Flag, "lazy_mode", translate("Enable Lazy Mode"))
o:depends("type", "hysteria2")
o.rmempty = true
o.default = "0"

o = s:option(Value, "obfs_type", translate("Obfuscation Type"))
o:depends({type = "hysteria2", flag_obfs = "1"})
o.rmempty = true
o.default = "salamander"

o = s:option(Value, "salamander", translate("Obfuscation Password"))
o:depends({type = "hysteria2", flag_obfs = "1"})
o.rmempty = true
o.default = "cry_me_a_r1ver"

o = s:option(Flag, "flag_quicparam", translate("Hysterir QUIC parameters"))
o:depends("type", "hysteria2")
o.rmempty = true
o.default = "0"

o = s:option(Flag, "disablepathmtudiscovery", translate("Disable QUIC path MTU discovery"))
o:depends({type = "hysteria2",flag_quicparam = "1"})
o.rmempty = true
o.default = false

--[[Hysteria2 QUIC parameters setting]]
o = s:option(Value, "initstreamreceivewindow", translate("QUIC initStreamReceiveWindow"))
o:depends({type = "hysteria2", flag_quicparam = "1"})
o.datatype = "uinteger"
o.rmempty = true
o.default = "8388608"

o = s:option(Value, "maxstreamseceivewindow", translate("QUIC maxStreamReceiveWindow"))
o:depends({type = "hysteria2", flag_quicparam = "1"})
o.datatype = "uinteger"
o.rmempty = true
o.default = "8388608"

o = s:option(Value, "initconnreceivewindow", translate("QUIC initConnReceiveWindow"))
o:depends({type = "hysteria2", flag_quicparam = "1"})
o.datatype = "uinteger"
o.rmempty = true
o.default = "20971520"

o = s:option(Value, "maxconnreceivewindow", translate("QUIC maxConnReceiveWindow"))
o:depends({type = "hysteria2", flag_quicparam = "1"})
o.datatype = "uinteger"
o.rmempty = true
o.default = "20971520"

o = s:option(Value, "maxidletimeout", translate("QUIC maxIdleTimeout(Unit:second)"))
o:depends({type = "hysteria2", flag_quicparam = "1"})
o.rmempty = true
o.datatype = "uinteger"
o.default = "30"

o = s:option(Value, "keepaliveperiod", translate("The keep-alive period.(Unit:second)"))
o.description = translate("Default value 0 indicatesno heartbeat.")
o:depends({type = "hysteria2", flag_quicparam = "1"})
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.rmempty = true
o.datatype = "uinteger"
o.default = "10"


--[[ Shadow-TLS Options ]]
o = s:option(ListValue, "shadowtls_protocol", translate("shadowTLS protocol Version"))
o:depends("type", "shadowtls")
o:value("v3", translate("Enable V3 protocol."))
o:value("v2", translate("Enable V2 protocol."))
o.default = "v3"
o.rmempty = true

o = s:option(Flag, "strict", translate("TLS 1.3 Strict mode"))
o:depends("type", "shadowtls")
o.default = "1"
o.rmempty = false

o = s:option(Flag, "fastopen", translate("TCP Fast Open"), translate("Enabling TCP Fast Open Requires Server Support."))
o:depends("type", "shadowtls")
o.default = "0"
o.rmempty = false

o = s:option(Flag, "disable_nodelay", translate("Disable TCP No_delay"))
o:depends("type", "shadowtls")
o.default = "0"
o.rmempty = true

o = s:option(Value, "shadowtls_sni", translate("shadow-TLS SNI"))
o:depends("type", "shadowtls")
o.datatype = "host"
o.rmempty = true
o.default = ""

--[[ add a ListValue for Choose chain type,sslocal or vmess ]]
o = s:option(ListValue, "chain_type", translate("Shadow-TLS ChainPoxy type"))
o:depends("type", "shadowtls")
if is_finded("sslocal") then
	o:value("sslocal", translate("ShadowSocks-rust Version"))
end
if is_finded("xray") or is_finded("v2ray") then
	o:value("vmess", translate("Vmess Protocol"))
end
o.default = "sslocal"
o.rmempty = false

o = s:option(Value, "sslocal_password",translate("Shadowsocks password"))
o:depends({type = "shadowtls", chain_type = "sslocal"})
o.rmempty = true

o = s:option(ListValue, "sslocal_method", translate("Encrypt Method"))
o:depends({type = "shadowtls", chain_type = "sslocal"})
for _, v in ipairs(encrypt_methods_ss) do
	o:value(v)
end

o = s:option(Value, "vmess_uuid", translate("Vmess UUID"))
o:depends({type = "shadowtls", chain_type = "vmess"})
o.rmempty = false
o.default = uuid

o = s:option(ListValue, "vmess_method", translate("Encrypt Method"))
o:depends({type = "shadowtls", chain_type = "vmess"})
for _, v in ipairs(securitys) do
	o:value(v, v:lower())
end
o.rmempty = true
o.default="auto"

-- [[ TUIC ]]
-- TuicNameId
o = s:option(Value, "tuic_uuid", translate("TUIC User UUID"))
o.rmempty = true
o.default = uuid
o:depends("type", "tuic")

--Tuic IP
o = s:option(Value, "tuic_ip", translate("TUIC Server IP Address"))
o.rmempty = true
o.datatype = "ip4addr"
o.default = ""
o:depends("type", "tuic")

-- Tuic Password
o = s:option(Value, "tuic_passwd", translate("TUIC User Password"))
o.rmempty = true
o.default = ""
o:depends("type", "tuic")

o = s:option(ListValue, "udp_relay_mode", translate("UDP relay mode"))
o:depends("type", "tuic")
o:value("native", translate("native UDP characteristics"))
o:value("quic", translate("lossless UDP relay using QUIC streams"))
o.default = "native"
o.rmempty = true

o = s:option(ListValue, "congestion_control", translate("Congestion control algorithm"))
o:depends("type", "tuic")
o:value("bbr", translate("BBR"))
o:value("cubic", translate("CUBIC"))
o:value("new_reno", translate("New Reno"))
o.default = "cubic"
o.rmempty = true

o = s:option(Value, "heartbeat", translate("Heartbeat interval(second)"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true

o = s:option(Value, "timeout", translate("Timeout for establishing a connection to server(second)"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = "8"
o.rmempty = true

o = s:option(Value, "gc_interval", translate("Garbage collection interval(second)"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true

o = s:option(Value, "gc_lifetime", translate("Garbage collection lifetime(second)"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = "15"
o.rmempty = true

o = s:option(Value, "send_window", translate("TUIC send window"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = 20971520
o.rmempty = true

o = s:option(Value, "receive_window", translate("TUIC receive window"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = 10485760
o.rmempty = true

o = s:option(Flag, "disable_sni", translate("Disable SNI"))
o:depends("type", "tuic")
o.default = "0"
o.rmempty = true

o = s:option(Flag, "zero_rtt_handshake", translate("Enable 0-RTT QUIC handshake"))
o:depends("type", "tuic")
o.default = "0"
o.rmempty = true

-- Tuic settings for the local inbound socks5 server
o = s:option(Flag, "tuic_dual_stack", translate("Dual-stack Listening Socket"))
o.description = translate("If this option is not set, the socket behavior is platform dependent.")
o:depends("type", "tuic")
o.default = "0"
o.rmempty = true

o = s:option(Value, "tuic_max_package_size", translate("Maximum packet size the socks5 server can receive from external"))
o:depends("type", "tuic")
o.datatype = "uinteger"
o.default = 1500
o.rmempty = true

-- AlterId
o = s:option(Value, "alter_id", translate("AlterId"))
o.datatype = "port"
o.default = 16
o.rmempty = true
o:depends({type = "v2ray", v2ray_protocol = "vmess"})

-- VmessId
o = s:option(Value, "vmess_id", translate("Vmess/VLESS ID (UUID)"))
o.rmempty = true
o.default = uuid
o:depends({type = "v2ray", v2ray_protocol = "vmess"})
o:depends({type = "v2ray", v2ray_protocol = "vless"})

-- VLESS Encryption
o = s:option(Value, "vless_encryption", translate("VLESS Encryption"))
o.rmempty = true
o.default = "none"
o:depends({type = "v2ray", v2ray_protocol = "vless"})

-- 加密方式
o = s:option(ListValue, "security", translate("Encrypt Method"))
for _, v in ipairs(securitys) do
	o:value(v, v:upper())
end
o.rmempty = true
o:depends({type = "v2ray", v2ray_protocol = "vmess"})

-- SOCKS Version
o = s:option(ListValue, "socks_ver", translate("Socks Version"))
o:value("4", "Socks4")
o:value("4a", "Socks4A")
o:value("5", "Socks5")
o.rmempty = true
o.default = "5"
o:depends({type = "v2ray", v2ray_protocol = "socks"})

-- 传输协议
o = s:option(ListValue, "transport", translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("kcp", "mKCP")
o:value("ws", "WebSocket")
o:value("httpupgrade", "HTTPUpgrade")
o:value("splithttp", "SplitHTTP")
o:value("xhttp", "XHTTP")
o:value("h2", "HTTP/2")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o.rmempty = true
o:depends({type = "v2ray", v2ray_protocol = "vless"})
o:depends({type = "v2ray", v2ray_protocol = "vmess"})
o:depends({type = "v2ray", v2ray_protocol = "trojan"})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o:depends({type = "v2ray", v2ray_protocol = "socks"})
o:depends({type = "v2ray", v2ray_protocol = "http"})

-- [[ RAW部分 ]]--
-- TCP伪装
o = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
o:depends("transport", "raw")
o:value("none", translate("None"))
o:value("http", "HTTP")
o.rmempty = true

-- HTTP域名
o = s:option(Value, "http_host", translate("HTTP Host"))
o:depends("tcp_guise", "http")
o.rmempty = true

-- HTTP路径
o = s:option(Value, "http_path", translate("HTTP Path"))
o:depends("tcp_guise", "http")
o.rmempty = true

-- [[ WS部分 ]]--
-- WS域名
o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({transport = "ws", tls = false})
o.datatype = "hostname"
o.rmempty = true

-- WS路径
o = s:option(Value, "ws_path", translate("WebSocket Path"))
o:depends("transport", "ws")
o.rmempty = true

if is_finded("v2ray") then
	-- WS前置数据
	o = s:option(Value, "ws_ed", translate("Max Early Data"))
	o:depends("ws_ed_enable", true)
	o.datatype = "uinteger"
	o:value("2048")
	o.rmempty = true

	-- WS前置数据标头
	o = s:option(Value, "ws_ed_header", translate("Early Data Header Name"))
	o:depends("ws_ed_enable", true)
	o:value("Sec-WebSocket-Protocol")
	o.rmempty = true
end

-- [[ httpupgrade部分 ]]--

-- httpupgrade域名
o = s:option(Value, "httpupgrade_host", translate("Httpupgrade Host"))
o:depends({transport = "httpupgrade", tls = false})
o.rmempty = true

-- httpupgrade路径
o = s:option(Value, "httpupgrade_path", translate("Httpupgrade Path"))
o:depends("transport", "httpupgrade")
o.rmempty = true

-- [[ splithttp部分 ]]--

-- splithttp域名
o = s:option(Value, "splithttp_host", translate("Splithttp Host"))
o:depends({transport = "splithttp", tls = false})
o.rmempty = true

-- splithttp路径
o = s:option(Value, "splithttp_path", translate("Splithttp Path"))
o:depends("transport", "splithttp")
o.rmempty = true

-- [[ XHTTP部分 ]]--
o = s:option(ListValue, "xhttp_alpn", translate("XHTTP Alpn"))
o.default = ""
o:value("", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends("transport", "xhttp")

o = s:option(ListValue, "xhttp_mode", translate("XHTTP Mode"))
o:depends("transport", "xhttp")
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

o = s:option(Value, "xhttp_host", translate("XHTTP Host"))
o:depends({transport = "xhttp", tls = false})
o.rmempty = true

o = s:option(Value, "xhttp_path", translate("XHTTP Path"))
o.placeholder = "/"
o:depends("transport", "xhttp")
o.rmempty = true

o = s:option(Flag, "enable_xhttp_extra", translate("XHTTP Extra"))
o.description = translate("Enable this option to configure XHTTP Extra (JSON format).")
o.rmempty = true
o.default = "0"
o:depends("transport", "xhttp")

o = s:option(TextValue, "xhttp_extra", " ")
o.description = translate(
    "<font><b>" .. translate("Configure XHTTP Extra Settings (JSON format), see:") .. "</b></font>" ..
    " <a href='https://xtls.github.io/config/transports/splithttp.html#extra' target='_blank'>" ..
    "<font style='color:green'><b>" .. translate("Click to the page") .. "</b></font></a>")
o:depends("enable_xhttp_extra", true)
o.rmempty = true
o.rows = 10
o.wrap = "off"
o.custom_write = function(self, section, value)
    m:set(section, "xhttp_extra", value)
    local success, data = pcall(luci.jsonc.parse, value)
    if success and data then
        local address = (data.extra and data.extra.downloadSettings and data.extra.downloadSettings.address)
            or (data.downloadSettings and data.downloadSettings.address)
        if address and address ~= "" then
            m:set(section, "download_address", address)
        else
            m:del(section, "download_address")
        end
    else
        m:del(section, "download_address")
    end
end
o.validate = function(self, value)
    value = value:gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
    if value:sub(-1) == "\n" then
        value = value:sub(1, -2)
    end
    local success, data = pcall(luci.jsonc.parse, value)
    if not success or not data then
        return nil, translate("Invalid JSON format")
    end

    return value
end

-- [[ H2部分 ]]--

-- H2域名
o = s:option(Value, "h2_host", translate("HTTP/2 Host"))
o:depends("transport", "h2")
o.rmempty = true

-- H2路径
o = s:option(Value, "h2_path", translate("HTTP/2 Path"))
o:depends("transport", "h2")
o.rmempty = true

-- gRPC
o = s:option(Value, "serviceName", translate("gRPC Service Name"))
o:depends("transport", "grpc")
o.rmempty = true

if is_finded("xray") then
	-- gPRC模式
	o = s:option(ListValue, "grpc_mode", translate("gRPC Mode"))
	o:depends("transport", "grpc")
	o:value("gun", translate("Gun"))
	o:value("multi", translate("Multi"))
	o.rmempty = true
end

if is_finded("xray") then
	-- gRPC初始窗口
	o = s:option(Value, "initial_windows_size", translate("Initial Windows Size"))
	o.datatype = "uinteger"
	o:depends("transport", "grpc")
	o.default = 0
	o.rmempty = true

	-- H2/gRPC健康检查
	o = s:option(Flag, "health_check", translate("H2/gRPC Health Check"))
	o:depends("transport", "h2")
	o:depends("transport", "grpc")
	o.rmempty = true

	o = s:option(Value, "read_idle_timeout", translate("H2 Read Idle Timeout"))
	o.datatype = "uinteger"
	o:depends({health_check = true, transport = "h2"})
	o.default = 60
	o.rmempty = true

	o = s:option(Value, "idle_timeout", translate("gRPC Idle Timeout"))
	o.datatype = "uinteger"
	o:depends({health_check = true, transport = "grpc"})
	o.default = 60
	o.rmempty = true

	o = s:option(Value, "health_check_timeout", translate("Health Check Timeout"))
	o.datatype = "uinteger"
	o:depends("health_check", 1)
	o.default = 20
	o.rmempty = true

	o = s:option(Flag, "permit_without_stream", translate("Permit Without Stream"))
	o:depends({health_check = true, transport = "grpc"})
	o.rmempty = true
end

-- [[ QUIC部分 ]]--
o = s:option(ListValue, "quic_security", translate("QUIC Security"))
o:depends("transport", "quic")
o:value("none", translate("None"))
o:value("aes-128-gcm", translate("aes-128-gcm"))
o:value("chacha20-poly1305", translate("chacha20-poly1305"))
o.rmempty = true

o = s:option(Value, "quic_key", translate("QUIC Key"))
o:depends("transport", "quic")
o.rmempty = true

o = s:option(ListValue, "quic_guise", translate("Header"))
o:depends("transport", "quic")
o.rmempty = true
o:value("none", translate("None"))
o:value("srtp", translate("VideoCall (SRTP)"))
o:value("utp", translate("BitTorrent (uTP)"))
o:value("wechat-video", translate("WechatVideo"))
o:value("dtls", translate("DTLS 1.2"))
o:value("wireguard", translate("WireGuard"))

-- [[ mKCP部分 ]]--
o = s:option(ListValue, "kcp_guise", translate("Camouflage Type"))
o:depends("transport", "kcp")
o:value("none", translate("None"))
o:value("srtp", translate("VideoCall (SRTP)"))
o:value("utp", translate("BitTorrent (uTP)"))
o:value("wechat-video", translate("WechatVideo"))
o:value("dtls", translate("DTLS 1.2"))
o:value("wireguard", translate("WireGuard"))
o.rmempty = true

o = s:option(Value, "mtu", translate("MTU"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
-- o.default = 1350
o.rmempty = true

o = s:option(Value, "tti", translate("TTI"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o.default = 50
o.rmempty = true

o = s:option(Value, "uplink_capacity", translate("Uplink Capacity(Default:Mbps)"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o:depends("type", "hysteria2")
o.default = 5
o.rmempty = true

o = s:option(Value, "downlink_capacity", translate("Downlink Capacity(Default:Mbps)"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o:depends("type", "hysteria2")
o.default = 20
o.rmempty = true

o = s:option(Value, "read_buffer_size", translate("Read Buffer Size"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o.default = 2
o.rmempty = true

o = s:option(Value, "write_buffer_size", translate("Write Buffer Size"))
o.datatype = "uinteger"
o:depends("transport", "kcp")
o.default = 2
o.rmempty = true

o = s:option(Value, "seed", translate("Obfuscate password (optional)"))
o:depends("transport", "kcp")
o.rmempty = true

o = s:option(Flag, "congestion", translate("Congestion"))
o:depends("transport", "kcp")
o.rmempty = true

-- [[ WireGuard 部分 ]]--
o = s:option(Flag, "kernelmode", translate("Enabled Kernel virtual NIC TUN(optional)"))
o.description = translate("Virtual NIC TUN of Linux kernel can be used only when system supports and have root permission. If used, IPv6 routing table 1023 is occupied.")
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.default = "0"
o.rmempty = true

o = s:option(DynamicList, "local_addresses", translate("Local addresses"))
o.datatype = "cidr"
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.rmempty = true

o = s:option(DynamicList, "reserved", translate("Reserved bytes(optional)"))
o.description = translate("Wireguard reserved bytes.")
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.rmempty = true

o = s:option(Value, "private_key", translate("Private key"))
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.password = true
o.rmempty = true

o = s:option(Value, "peer_pubkey", translate("Peer public key"))
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.rmempty = true

o = s:option(Value, "preshared_key", translate("Pre-shared key"))
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.password = true
o.rmempty = true

o = s:option(DynamicList, "allowedips", translate("allowedIPs(optional)"))
o.description = translate("Wireguard allows only traffic from specific source IP.")
o.datatype = "cidr"
o:depends({type = "v2ray", v2ray_protocol = "wireguard"})
o.default = "0.0.0.0/0"
o.rmempty = true

-- [[ TLS ]]--
o = s:option(Flag, "tls", translate("TLS"))
o.rmempty = true
o.default = "0"
o:depends({type = "v2ray", v2ray_protocol = "vless", reality = false})
o:depends({type = "v2ray", v2ray_protocol = "vmess", reality = false})
o:depends({type = "v2ray", v2ray_protocol = "trojan", reality = false})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks", reality = false})
o:depends({type = "v2ray", v2ray_protocol = "socks", socks_ver = "5", reality = false})
o:depends({type = "v2ray", v2ray_protocol = "http", reality = false})
o:depends("type", "trojan")
o:depends("type", "hysteria2")

-- [[ TLS部分 ]] --
o = s:option(Flag, "tls_sessionTicket", translate("Session Ticket"))
o:depends({type = "trojan", tls = true})
o.default = "0"

if is_finded("xray") then
	-- [[ REALITY ]]
	o = s:option(Flag, "reality", translate("REALITY"))
	o.rmempty = true
	o.default = "0"
	o:depends({type = "v2ray", v2ray_protocol = "vless", tls = false})

	o = s:option(Value, "reality_publickey", translate("Public key"))
	o.rmempty = true
	o:depends({type = "v2ray", v2ray_protocol = "vless", reality = true})

	o = s:option(Value, "reality_shortid", translate("Short ID"))
	o.rmempty = true
	o:depends({type = "v2ray", v2ray_protocol = "vless", reality = true})

	o = s:option(Value, "reality_spiderx", translate("spiderX"))
	o.rmempty = true
	o:depends({type = "v2ray", v2ray_protocol = "vless", reality = true})

	-- [[ XTLS ]]--
	o = s:option(ListValue, "tls_flow", translate("Flow"))
	for _, v in ipairs(tls_flows) do
		if v == "none" then
		   o.default = "none"
		   o:value("none", translate("none"))
		else
		    o:value(v, translate(v))
		end
	end
	o.rmempty = true
	o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "raw", tls = true})
	o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "raw", reality = true})

	o = s:option(ListValue, "xhttp_tls_flow", translate("Flow"))
	for _, v in ipairs(tls_flows) do
		if v == "none" then
		   o.default = "none"
		   o:value("none", translate("none"))
		else
		   o:value("xtls-rprx-vision", translate("xtls-rprx-vision"))
		end
	end
	o.rmempty = true
	o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "xhttp", tls = true})
	o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "xhttp", reality = true})

	-- [[ uTLS ]]--
	o = s:option(ListValue, "fingerprint", translate("Finger Print"))
	o.default = ""
	o:value("chrome", translate("chrome"))
	o:value("firefox", translate("firefox"))
	o:value("safari", translate("safari"))
	o:value("ios", translate("ios"))
	o:value("android", translate("android"))
	o:value("edge", translate("edge"))
	o:value("360", translate("360"))
	o:value("qq", translate("qq"))
	o:value("random", translate("random"))
	o:value("randomized", translate("randomized"))
	o:value("", translate("disable"))
	o:depends({type = "v2ray", tls = true})
	o:depends({type = "v2ray", reality = true})
end

o = s:option(Value, "tls_host", translate("TLS Host"))
o.datatype = "hostname"
o:depends("tls", true)
o:depends("xtls", true)
o:depends("reality", true)
o.rmempty = true

o = s:option(DynamicList, "tls_alpn", translate("TLS ALPN"))
o:depends("type", "tuic")
o.default = "h3"
o.rmempty = true

-- [[ allowInsecure ]]--
o = s:option(Flag, "insecure", translate("allowInsecure"))
o.rmempty = false
o:depends("tls", true)
o:depends("type", "hysteria2")
o.description = translate("If true, allowss insecure connection at TLS client, e.g., TLS server uses unverifiable certificates.")

-- [[ Hysteria2 TLS pinSHA256 ]] --
o = s:option(Value, "pinsha256", translate("Certificate fingerprint"))
o:depends({type = "hysteria2", insecure = true })
o.rmempty = true


-- [[ Mux.Cool ]] --
o = s:option(Flag, "mux", translate("Mux"), translate("Enable Mux.Cool"))
o.rmempty = false
o.default = false
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "raw"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "ws"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "kcp"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "httpupgrade"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "splithttp"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "h2"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "quic"})
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "grpc"})
o:depends({type = "v2ray", v2ray_protocol = "vmess"})
o:depends({type = "v2ray", v2ray_protocol = "trojan"})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o:depends({type = "v2ray", v2ray_protocol = "socks"})
o:depends({type = "v2ray", v2ray_protocol = "http"})

-- [[ XUDP Mux ]] --
o = s:option(Flag, "xmux", translate("Xudp Mux"), translate("Enable Xudp Mux"))
o.rmempty = false
o.default = false
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "xhttp"})

-- [[ TCP 最大并发连接数 ]]--
o = s:option(Value, "concurrency", translate("concurrency"))
o.description = translate(
		"<ul>"
		.. "<li>" .. translate("Default: disable. When entering a negative number, such as -1, The Mux module will not be used to carry TCP traffic.") .. "</li>"
		.. "<li>" .. translate("Min value is 1, Max value is 128. When omitted or set to 0, it equals 8.") .. "</li>"
		.. "</ul>")
o.rmempty = true
o.default = "-1"
o:value("-1", translate("disable"))
o:value("8", translate("8"))
o:depends("mux", true)

-- [[ UDP 最大并发连接数 ]]--
o = s:option(Value, "xudpConcurrency", translate("xudpConcurrency"))
o.description = translate(
		"<ul>"
		.. "<li>" .. translate("Default:16. When entering a negative number, such as -1, The Mux module will not be used to carry UDP traffic, Use original UDP transmission method of proxy protocol.") .. "</li>"
		.. "<li>" .. translate("Min value is 1, Max value is 1024. When omitted or set to 0, Will same path as TCP traffic.") .. "</li>"
		.. "</ul>")
o.rmempty = true
o.default = "16"
o:value("-1", translate("disable"))
o:value("16", translate("16"))
o:depends("mux", true)
o:depends("xmux", true)

-- [[ 对被代理的 UDP/443 流量处理方式 ]]--
o = s:option(ListValue, "xudpProxyUDP443", translate("xudpProxyUDP443"))
o.description = translate(
		"<ul>"
		.. "<li>" .. translate("Default reject rejects traffic.") .. "</li>"
		.. "<li>" .. translate("allow: Allows use Mux connection.") .. "</li>"
		.. "<li>" .. translate("skip: Not use Mux module to carry UDP 443 traffic, Use original UDP transmission method of proxy protocol.") .. "</li>"
		.. "</ul>")
o.rmempty = true
o.default = "reject"
o:value("reject", translate("reject"))
o:value("allow", translate("allow"))
o:value("skip", translate("skip"))
o:depends("mux", true)

-- [[ XHTTP TCP Fast Open ]]--
o = s:option(Flag, "tcpfastopen", translate("TCP Fast Open"), translate("Enabling TCP Fast Open Requires Server Support."))
o.rmempty = true
o.default = "0"
o:depends({type = "v2ray", v2ray_protocol = "vless", transport = "xhttp"})

-- [[ MPTCP ]]--
o = s:option(Flag, "mptcp", translate("MPTCP"), translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.rmempty = true
o.default = "0"
o:depends({type = "v2ray", v2ray_protocol = "vless"})
o:depends({type = "v2ray", v2ray_protocol = "vmess"})
o:depends({type = "v2ray", v2ray_protocol = "trojan"})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o:depends({type = "v2ray", v2ray_protocol = "socks"})
o:depends({type = "v2ray", v2ray_protocol = "http"})

-- [[ custom_tcpcongestion 连接服务器节点的 TCP 拥塞控制算法 ]]--
o = s:option(ListValue, "custom_tcpcongestion", translate("custom_tcpcongestion"))
o.rmempty = true
o.default = ""
o:value("", translate("comment_tcpcongestion_disable"))
o:value("bbr", translate("BBR"))
o:value("cubic", translate("CUBIC"))
o:value("reno", translate("Reno"))
o:depends({type = "v2ray", v2ray_protocol = "vless"})
o:depends({type = "v2ray", v2ray_protocol = "vmess"})
o:depends({type = "v2ray", v2ray_protocol = "trojan"})
o:depends({type = "v2ray", v2ray_protocol = "shadowsocks"})
o:depends({type = "v2ray", v2ray_protocol = "socks"})
o:depends({type = "v2ray", v2ray_protocol = "http"})


-- [[ Cert ]]--
o = s:option(Flag, "certificate", translate("Self-signed Certificate"))
o.rmempty = true
o.default = "0"
o:depends("type", "tuic")
o:depends({type = "hysteria2", insecure = false})
o:depends({type = "trojan", tls = true, insecure = false})
o:depends({type = "v2ray", v2ray_protocol = "vmess", tls = true, insecure = false})
o:depends({type = "v2ray", v2ray_protocol = "vless", tls = true, insecure = false})
o.description = translate("If you have a self-signed certificate,please check the box")

o = s:option(DummyValue, "upload", translate("Upload"))
o.template = "shadowsocksr/certupload"
o:depends("certificate", 1)

cert_dir = "/etc/ssl/private/"
local path

luci.http.setfilehandler(function(meta, chunk, eof)
	if not fd then
		if (not meta) or (not meta.name) or (not meta.file) then
			return
		end
		fd = nixio.open(cert_dir .. meta.file, "w")
		if not fd then
			path = translate("Create upload file error.")
			return
		end
	end
	if chunk and fd then
		fd:write(chunk)
	end
	if eof and fd then
		fd:close()
		fd = nil
		path = '/etc/ssl/private/' .. meta.file .. ''
	end
end)
if luci.http.formvalue("upload") then
	local f = luci.http.formvalue("ulfile")
	if #f <= 0 then
		path = translate("No specify upload file.")
	end
end

o = s:option(Value, "certpath", translate("Current Certificate Path"))
o:depends("certificate", 1)
o:value("/etc/ssl/private/ca.crt")
o.description = translate("Please confirm the current certificate path")
o.default = "/etc/ssl/private/ca.crt"

o = s:option(Flag, "fast_open", translate("TCP Fast Open"), translate("Enabling TCP Fast Open Requires Server Support."))
o.rmempty = true
o.default = "0"
o:depends("type", "ssr")
o:depends("type", "ss")
o:depends("type", "trojan")
o:depends("type", "hysteria2")

o = s:option(Flag, "switch_enable", translate("Enable Auto Switch"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "local_port", translate("Local Port"))
o.datatype = "port"
o.default = 1234
o.rmempty = false

if is_finded("kcptun-client") then
	o = s:option(Flag, "kcp_enable", translate("KcpTun Enable"))
	o.rmempty = true
	o.default = "0"
	o:depends("type", "ssr")
	o:depends("type", "ss")

	o = s:option(Value, "kcp_port", translate("KcpTun Port"))
	o.datatype = "portrange"
	o.default = 4000
	o:depends("type", "ssr")
	o:depends("type", "ss")

	o = s:option(Value, "kcp_password", translate("KcpTun Password"))
	o.password = true
	o:depends("type", "ssr")
	o:depends("type", "ss")

	o = s:option(Value, "kcp_param", translate("KcpTun Param"))
	o.default = "--nocomp"
	o:depends("type", "ssr")
	o:depends("type", "ss")
end

return m


