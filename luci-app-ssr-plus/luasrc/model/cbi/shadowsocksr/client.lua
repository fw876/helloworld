-- Copyright (C) 2017 yushi studio <ywb94@qq.com> github.com/ywb94
-- Copyright (C) 2018 lean <coolsnowwolf@gmail.com> github.com/coolsnowwolf
-- Licensed to the public under the GNU General Public License v3.

local m, s, sec, o
local uci = require "luci.model.uci".cursor()
local URL = require "url"
local sys = require "luci.sys"
local util = require "luci.util"
local datatypes = require "luci.cbi.datatypes"

-- 获取 LAN IP 地址
function lanip()
	local lan_ip

	-- 尝试从 UCI 直接读取
	lan_ip = sys.exec("uci -q get network.lan.ipaddr 2>/dev/null | awk -F'/' '{print $1}' | tr -d '\\n'")

	-- 尝试从 LAN 接口信息中读取（优先 ifname，再 fallback 到 device）
	if not lan_ip or lan_ip == "" then
		lan_ip = sys.exec([[
ip -4 addr show $(uci -q -p /tmp/state get network.lan.ifname || uci -q -p /tmp/state get network.lan.device) 2>/dev/null \
  | grep -w 'inet' | awk '{print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 | tr -d '\n']])
	end

	-- 取任意一个 global IPv4 地址
	if not lan_ip or lan_ip == "" then
		lan_ip = sys.exec([[
ip -4 addr show scope global 2>/dev/null \
  | grep -w 'inet' | awk '{print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 | tr -d '\n']])
	end

	return lan_ip
end

local lan_ip = lanip()
local clash_nodes = {}
local function is_finded(e)
	return sys.exec(string.format('type -t -p "%s" -p "/usr/libexec/%s" 2>/dev/null', e, e)) ~= ""
end

local function clash_display_name(s)
	if s.type ~= "clash" or not s.clash_url or s.clash_url == "" then
		return nil
	end
	local ok, parsed = pcall(URL.parse, s.clash_url)
	if ok and parsed and parsed.host then
		return "[CLASH]:" .. parsed.host
	end
	return "[CLASH]"
end

local function is_valid_dns(str)
	if datatypes.ip4addrport(str) then
		return true
	end

	local scheme, target = str:match("^([a-zA-Z0-9%+%-%.]+)://(.+)$")
	if scheme and target and #target > 0 then
		return true
	end

	local host = str:match("^([^:]+):%d+$") or str
	if host:match("[a-zA-Z]") 
	   and not host:match("[^%w%.%-]") 
	   and not host:match("^[%.%-]") 
	   and not host:match("[%.%-]$") 
	   and not host:match("%.%.") then
		return true
	end

	return false
end

m = Map("shadowsocksr", translate("ShadowSocksR Plus+ Settings"), translate("<h3>Support SS/SSR/V2RAY/XRAY/TROJAN/TUIC/HYSTERIA2/NAIVEPROXY/SOCKS5/CLASH etc.</h3>"))
m:section(SimpleSection).template = "shadowsocksr/status"

local server_table = {}
local server_order = {}
uci:foreach("shadowsocksr", "servers", function(s)
	if s.type == "clash" then
		clash_nodes[s[".name"]] = true
	end

	if s.type ~= "tun" and s.alias then
		server_table[s[".name"]] = "[%s]:%s" % {string.upper(s.v2ray_protocol or s.type), s.alias}
	elseif s.type ~= "tun" and s.server and s.server_port then
		server_table[s[".name"]] = "[%s]:%s:%s" % {string.upper(s.v2ray_protocol or s.type), s.server, s.server_port}
	elseif s.type ~= "tun" then
		local display_name = clash_display_name(s)
		if display_name then
			server_table[s[".name"]] = display_name
		end
	end
	if s.type ~= "tun" and server_table[s[".name"]] then
		table.insert(server_order, s[".name"])
	end
end)

-- [[ Global Setting ]]--
s = m:section(TypedSection, "global")
s.anonymous = true

o = s:option(ListValue, "global_server", translate("Main Server"))
o:value("nil", translate("Disable"))
for _, key in ipairs(server_order) do
	o:value(key, server_table[key])
end
o.default = "nil"
o.rmempty = false

o = s:option(DummyValue, "_clash_panel", translate("Clash Panel"))
o.template = "shadowsocksr/clash_main_panel"
o.clash_nodes = clash_nodes

o = s:option(ListValue, "threads", translate("Multi Threads Option"))
o:value("0", translate("Auto Threads"))
o:value("1", translate("1 Thread"))
o:value("2", translate("2 Threads"))
o:value("4", translate("4 Threads"))
o:value("8", translate("8 Threads"))
o:value("16", translate("16 Threads"))
o:value("32", translate("32 Threads"))
o:value("64", translate("64 Threads"))
o:value("128", translate("128 Threads"))
o.default = "0"
o.rmempty = false

o = s:option(ListValue, "run_mode", translate("Running Mode"))
o:value("gfw", translate("GFW List Mode"))
o:value("router", translate("IP Route Mode"))
o:value("all", translate("Global Mode"))
o.default = gfw

o = s:option(ListValue, "dports", translate("Proxy Ports"))
o:value("1", translate("All Ports"))
o:value("2", translate("Only Common Ports"))
o:value("3", translate("Custom Ports"))
cp = s:option(Value, "custom_ports", translate("Enter Custom Ports"))
cp:depends("dports", "3")  -- 仅当用户选择“Custom Ports”时显示
cp.placeholder = "e.g., 80,443,8080"
o.default = 1

o = s:option(ListValue, "pdnsd_enable", translate("Resolve Dns Mode"))
if is_finded("dns2tcp") then
	o:value("1", translate("Use DNS2TCP query"))
end
if is_finded("mosdns") then
	o:value("4", translate("Use MosDNS query"))
end
if is_finded("chinadns-ng") then
	o:value("6", translate("Use ChinaDNS-NG query and cache"))
end
o:value("7", translate("Prefer module built-in DNS"))
o:value("0", translate("Use Local DNS Service listen port 5335"))
o.default = 1

o = s:option(Value, "dns2tcp_tunnel_forward", translate("Anti-pollution DNS Server"))
o:value("8.8.4.4:53", translate("Google Public DNS (8.8.4.4)"))
o:value("8.8.8.8:53", translate("Google Public DNS (8.8.8.8)"))
o:value("208.67.222.222:53", translate("OpenDNS (208.67.222.222)"))
o:value("208.67.220.220:53", translate("OpenDNS (208.67.220.220)"))
o:value("209.244.0.3:53", translate("Level 3 Public DNS (209.244.0.3)"))
o:value("209.244.0.4:53", translate("Level 3 Public DNS (209.244.0.4)"))
o:value("4.2.2.1:53", translate("Level 3 Public DNS (4.2.2.1)"))
o:value("4.2.2.2:53", translate("Level 3 Public DNS (4.2.2.2)"))
o:value("4.2.2.3:53", translate("Level 3 Public DNS (4.2.2.3)"))
o:value("4.2.2.4:53", translate("Level 3 Public DNS (4.2.2.4)"))
o:value("1.1.1.1:53", translate("Cloudflare DNS (1.1.1.1)"))
o:depends("pdnsd_enable", "1")
o.description = translate("Custom DNS Server format as IP:PORT (default: 8.8.4.4:53)")
o.datatype = "ip4addrport"
o.default = "8.8.4.4:53"

o = s:option(Value, "tunnel_forward", translate("Anti-pollution DNS Server"))
o:value("8.8.4.4:53", translate("Google Public DNS (8.8.4.4)"))
o:value("8.8.8.8:53", translate("Google Public DNS (8.8.8.8)"))
o:value("208.67.222.222:53", translate("OpenDNS (208.67.222.222)"))
o:value("208.67.220.220:53", translate("OpenDNS (208.67.220.220)"))
o:value("209.244.0.3:53", translate("Level 3 Public DNS (209.244.0.3)"))
o:value("209.244.0.4:53", translate("Level 3 Public DNS (209.244.0.4)"))
o:value("4.2.2.1:53", translate("Level 3 Public DNS (4.2.2.1)"))
o:value("4.2.2.2:53", translate("Level 3 Public DNS (4.2.2.2)"))
o:value("4.2.2.3:53", translate("Level 3 Public DNS (4.2.2.3)"))
o:value("4.2.2.4:53", translate("Level 3 Public DNS (4.2.2.4)"))
o:value("1.1.1.1:53", translate("Cloudflare DNS (1.1.1.1)"))
o:depends("pdnsd_enable", "7")
o.datatype = nil
o.description =
	"<ul>" ..
	"<li>" .. translate("Custom DNS Server (supports format IP:PORT, domain name, or scheme://...).") .. "</li>" ..
	"<li>" .. translate("Muitiple DNS server can saperate with ','") .. "</li>" ..
	"<li>" .. translate("Note: IP addresses MUST specify a port.") .. "</li>" ..
	"</ul>"
o.default = "8.8.4.4:53"
o.validate = function(self, value, section)
	if section and value and value ~= "" then
		local parts = {}
		for part in (value .. ","):gmatch("(.-),") do
			part = part:gsub("^%s*", ""):gsub("%s*$", "")
			if part ~= "" then
				if not is_valid_dns(part) then
					return nil, translate("Expecting: %s"):format(translate("IP:PORT, Domain, or Protocol URL (e.g. 8.8.8.8:53, dns.google, https://...).") ..
						"<br>".. translate("Note: Pure IP without port is not allowed."))
				end
				table.insert(parts, part)
			end
		end

		if #parts > 0 then
			return table.concat(parts, ",")
		end

		return nil, translate("Expecting: %s"):format(translate("valid address:port")) -- 有效的地址:端口
	end

	return value
end

o = s:option(Value, "tunnel_forward_mosdns", translate("Anti-pollution DNS Server"))
o:value("tcp://8.8.4.4:53,tcp://8.8.8.8:53", translate("Google Public DNS"))
o:value("tcp://208.67.222.222:53,tcp://208.67.220.220:53", translate("OpenDNS"))
o:value("tcp://209.244.0.3:53,tcp://209.244.0.4:53", translate("Level 3 Public DNS-1 (209.244.0.3-4)"))
o:value("tcp://4.2.2.1:53,tcp://4.2.2.2:53", translate("Level 3 Public DNS-2 (4.2.2.1-2)"))
o:value("tcp://4.2.2.3:53,tcp://4.2.2.4:53", translate("Level 3 Public DNS-3 (4.2.2.3-4)"))
o:value("tcp://1.1.1.1:53,tcp://1.0.0.1:53", translate("Cloudflare DNS"))
o:depends("pdnsd_enable", "4")
o.description = translate("Custom DNS Server format as tcp://IP:PORT or tls://DOMAIN:PORT (tcp://8.8.8.8 or tls://dns.google:853)")
o.default = "tcp://8.8.4.4:53,tcp://8.8.8.8:53"

o = s:option(Flag, "filter_aaaa", translate("Disable IPv6 for Overseas FQDN"))
o:depends("pdnsd_enable", "1")
o:depends("pdnsd_enable", "4")
o:depends("pdnsd_enable", "7")
o.rmempty = false
o.default = "1"

if is_finded("chinadns-ng") then
	o = s:option(Value, "chinadns_ng_tunnel_forward", translate("Anti-pollution DNS Server"))
	o:value("8.8.4.4:53", translate("Google Public DNS (8.8.4.4)"))
	o:value("8.8.8.8:53", translate("Google Public DNS (8.8.8.8)"))
	o:value("208.67.222.222:53", translate("OpenDNS (208.67.222.222)"))
	o:value("208.67.220.220:53", translate("OpenDNS (208.67.220.220)"))
	o:value("209.244.0.3:53", translate("Level 3 Public DNS (209.244.0.3)"))
	o:value("209.244.0.4:53", translate("Level 3 Public DNS (209.244.0.4)"))
	o:value("4.2.2.1:53", translate("Level 3 Public DNS (4.2.2.1)"))
	o:value("4.2.2.2:53", translate("Level 3 Public DNS (4.2.2.2)"))
	o:value("4.2.2.3:53", translate("Level 3 Public DNS (4.2.2.3)"))
	o:value("4.2.2.4:53", translate("Level 3 Public DNS (4.2.2.4)"))
	o:value("1.1.1.1:53", translate("Cloudflare DNS (1.1.1.1)"))
	o:depends("pdnsd_enable", "6")
	o.default = "8.8.4.4:53"
	o.description = translate(
		"<ul>" ..
		"<li>" .. translate("Custom DNS Server format as IP:PORT (default: 8.8.4.4:53)") .. "</li>" .. 
		"<li>" .. translate("Muitiple DNS server can saperate with ','") .. "</li>" ..
		"</ul>"
	)

	o = s:option(ListValue, "chinadns_ng_proto", translate("ChinaDNS-NG query protocol"))
	o:value("none", translate("UDP/TCP upstream"))
	o:value("tcp", translate("TCP upstream"))
	o:value("udp", translate("UDP upstream"))
	o:value("tls", translate("DoT upstream (Need use wolfssl version)"))
	o:depends("pdnsd_enable", "6")

	o = s:option(Value, "chinadns_forward", translate("Domestic DNS Server"))
	o:value("none", translate("Disable ChinaDNS-NG"))
	o:value("wan", translate("Use DNS from WAN"))
	o:value("wan_114", translate("Use DNS from WAN and 114DNS"))
	o:value("114.114.114.114:53", translate("Nanjing Xinfeng 114DNS (114.114.114.114)"))
	o:value("119.29.29.29:53", translate("DNSPod Public DNS (119.29.29.29)"))
	o:value("223.5.5.5:53", translate("AliYun Public DNS (223.5.5.5)"))
	o:value("180.76.76.76:53", translate("Baidu Public DNS (180.76.76.76)"))
	o:value("101.226.4.6:53", translate("360 Security DNS (China Telecom) (101.226.4.6)"))
	o:value("123.125.81.6:53", translate("360 Security DNS (China Unicom) (123.125.81.6)"))
	o:value("1.2.4.8:53", translate("CNNIC SDNS (1.2.4.8)"))
	o:depends({pdnsd_enable = "6", run_mode = "router"})
	o.default = "wan"
	o.description = translate(
		"<ul>" ..
		"<li>" .. translate("Custom DNS Server format as IP:PORT (default: disabled)") .. "</li>" .. 
		"<li>" .. translate("Muitiple DNS server can saperate with ','") .. "</li>" ..
		"</ul>"
	)
	o.validate = function(self, value, section)
		if (section and value) then
			if value == "none" or value == "wan" or value == "wan_114" then
				return value
			end

			if string.find(value, ",") then
				local parts = {}
				for part in string.gmatch(value, "[^,]+") do
					part = part:gsub("^%s*", ""):gsub("%s*$", "")
					if not datatypes.ip4addrport(part) then
						return nil, translate("Expecting: %s"):format(translate("valid address:port (comma separated)"))
					end
					table.insert(parts, part)
				end
				if #parts == 0 then
					return nil, translate("Expecting: %s"):format(translate("valid address:port"))
				end
				return table.concat(parts, ",")
			end

			if datatypes.ip4addrport(value) then
				return value
			end

			return nil, translate("Expecting: %s"):format(translate("valid address:port"))
		end

		return value
	end
end

local dns_defaults_section = m:section(SimpleSection)
dns_defaults_section.template = "shadowsocksr/client_dns_defaults"

return m
