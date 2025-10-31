-- Copyright (C) 2017 yushi studio <ywb94@qq.com> github.com/ywb94
-- Copyright (C) 2018 lean <coolsnowwolf@gmail.com> github.com/coolsnowwolf
-- Licensed to the public under the GNU General Public License v3.

local m, s, sec, o
local uci = require "luci.model.uci".cursor()

-- 获取 LAN IP 地址
function lanip()
	local lan_ip

	-- 尝试从 UCI 直接读取
	lan_ip = luci.sys.exec("uci -q get network.lan.ipaddr 2>/dev/null | awk -F'/' '{print $1}' | tr -d '\\n'")

	-- 尝试从 LAN 接口信息中读取（优先 ifname，再 fallback 到 device）
	if not lan_ip or lan_ip == "" then
		lan_ip = luci.sys.exec([[
ip -4 addr show $(uci -q -p /tmp/state get network.lan.ifname || uci -q -p /tmp/state get network.lan.device) 2>/dev/null \
  | grep -w 'inet' | awk '{print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 | tr -d '\n']])
	end

	-- 取任意一个 global IPv4 地址
	if not lan_ip or lan_ip == "" then
		lan_ip = luci.sys.exec([[
ip -4 addr show scope global 2>/dev/null \
  | grep -w 'inet' | awk '{print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 | tr -d '\n']])
	end

	return lan_ip
end

local lan_ip = lanip()
local validation = require "luci.cbi.datatypes"
local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" 2>/dev/null', e)) ~= ""
end

m = Map("shadowsocksr", translate("ShadowSocksR Plus+ Settings"), translate("<h3>Support SS/SSR/V2RAY/XRAY/TROJAN/TUIC/HYSTERIA2/NAIVEPROXY/SOCKS5/TUN etc.</h3>"))
m:section(SimpleSection).template = "shadowsocksr/status"

local server_table = {}
uci:foreach("shadowsocksr", "servers", function(s)
	if s.alias then
		server_table[s[".name"]] = "[%s]:%s" % {string.upper(s.v2ray_protocol or s.type), s.alias}
	elseif s.server and s.server_port then
		server_table[s[".name"]] = "[%s]:%s:%s" % {string.upper(s.v2ray_protocol or s.type), s.server, s.server_port}
	end
end)

local key_table = {}
for key, _ in pairs(server_table) do
	table.insert(key_table, key)
end

table.sort(key_table)

-- [[ Global Setting ]]--
s = m:section(TypedSection, "global")
s.anonymous = true

o = s:option(ListValue, "global_server", translate("Main Server"))
o:value("nil", translate("Disable"))
for _, key in pairs(key_table) do
	o:value(key, server_table[key])
end
o.default = "nil"
o.rmempty = false

o = s:option(ListValue, "udp_relay_server", translate("Game Mode UDP Server"))
o:value("", translate("Disable"))
o:value("same", translate("Same as Global Server"))
for _, key in pairs(key_table) do
	o:value(key, server_table[key])
end

if uci:get_first("shadowsocksr", 'global', 'netflix_enable', '0') == '1' then
	o = s:option(ListValue, "netflix_server", translate("Netflix Node"))
	o:value("nil", translate("Disable"))
	o:value("same", translate("Same as Global Server"))
	for _, key in pairs(key_table) do
		o:value(key, server_table[key])
	end
	o.default = "nil"
	o.rmempty = false

	o = s:option(Flag, "netflix_proxy", translate("External Proxy Mode"))
	o.rmempty = false
	o.description = translate("Forward Netflix Proxy through Main Proxy")
	o.default = "0"
end

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
o:value("oversea", translate("Oversea Mode"))
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
if is_finded("dns2socks") then
	o:value("2", translate("Use DNS2SOCKS query and cache"))
end
if is_finded("dns2socks-rust") then
	o:value("3", translate("Use DNS2SOCKS-RUST query and cache"))
end
if is_finded("mosdns") then
	o:value("4", translate("Use MOSDNS query (Not Support Oversea Mode)"))
end
if is_finded("dnsproxy") then
	o:value("5", translate("Use DNSPROXY query and cache"))
end
if is_finded("chinadns-ng") then
	o:value("6", translate("Use ChinaDNS-NG query and cache"))
end
o:value("0", translate("Use Local DNS Service listen port 5335"))
o.default = 1

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
o:value("114.114.114.114:53", translate("Oversea Mode DNS-1 (114.114.114.114)"))
o:value("114.114.115.115:53", translate("Oversea Mode DNS-2 (114.114.115.115)"))
o:depends("pdnsd_enable", "1")
o:depends("pdnsd_enable", "2")
o:depends("pdnsd_enable", "3")
o.description = translate("Custom DNS Server format as IP:PORT (default: 8.8.4.4:53)")
o.datatype = "ip4addrport"
o.default = "8.8.4.4:53"

o = s:option(ListValue, "tunnel_forward_mosdns", translate("Anti-pollution DNS Server"))
o:value("tcp://8.8.4.4:53,tcp://8.8.8.8:53", translate("Google Public DNS"))
o:value("tcp://208.67.222.222:53,tcp://208.67.220.220:53", translate("OpenDNS"))
o:value("tcp://209.244.0.3:53,tcp://209.244.0.4:53", translate("Level 3 Public DNS-1 (209.244.0.3-4)"))
o:value("tcp://4.2.2.1:53,tcp://4.2.2.2:53", translate("Level 3 Public DNS-2 (4.2.2.1-2)"))
o:value("tcp://4.2.2.3:53,tcp://4.2.2.4:53", translate("Level 3 Public DNS-3 (4.2.2.3-4)"))
o:value("tcp://1.1.1.1:53,tcp://1.0.0.1:53", translate("Cloudflare DNS"))
o:depends("pdnsd_enable", "4")
o.description = translate("Custom DNS Server for MosDNS")

o = s:option(Flag, "mosdns_ipv6", translate("Disable IPv6 in MOSDNS query mode"))
o:depends("pdnsd_enable", "4")
o.rmempty = false
o.default = "1"

if is_finded("dnsproxy") then
	o = s:option(ListValue, "parse_method", translate("Select DNS parse Mode"))
	o.description = translate(
    	"<ul>" ..
    	"<li>" .. translate("When use DNS list file, please ensure list file exists and is formatted correctly.") .. "</li>" ..
    	"<li>" .. translate("Tips: Dnsproxy DNS Parse List Path:") ..
    	" <a href='http://" .. lan_ip .. "/cgi-bin/luci/admin/services/shadowsocksr/control' target='_blank'>" ..
    	translate("Click here to view or manage the DNS list file") .. "</a>" .. "</li>" ..
    	"</ul>"
	)
	o:value("single_dns", translate("Set Single DNS"))
	o:value("parse_file", translate("Use DNS List File"))
	o:depends("pdnsd_enable", "5")
	o.rmempty = true
	o.default = "single_dns"

	o = s:option(Value, "dnsproxy_tunnel_forward", translate("Anti-pollution DNS Server"))
	o:value("sdns://AgUAAAAAAAAABzguOC40LjQgsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjQuNAovZG5zLXF1ZXJ5", translate("Google DNSCrypt SDNS"))
	o:value("sdns://AgcAAAAAAAAAACC2vD25TAYM7EnyCH8Xw1-0g5OccnTsGH9vQUUH0njRtAxkbnMudHduaWMudHcKL2Rucy1xdWVyeQ", translate("TWNIC-101 DNSCrypt SDNS"))
	o:value("sdns://AgcAAAAAAAAADzE4NS4yMjIuMjIyLjIyMiAOp5Svj-oV-Fz-65-8H2VKHLKJ0egmfEgrdPeAQlUFFA8xODUuMjIyLjIyMi4yMjIKL2Rucy1xdWVyeQ", translate("dns.sb DNSCrypt SDNS"))
	o:value("sdns://AgMAAAAAAAAADTE0OS4xMTIuMTEyLjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8SZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk", translate("Quad9 DNSCrypt SDNS"))
	o:value("sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20", translate("AdGuard DNSCrypt SDNS"))
	o:value("sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk", translate("Cloudflare DNSCrypt SDNS"))
	o:value("sdns://AgcAAAAAAAAADjEwNC4xNi4yNDkuMjQ5ABJjbG91ZGZsYXJlLWRucy5jb20KL2Rucy1xdWVyeQ", translate("cloudflare-dns.com DNSCrypt SDNS"))
	o:depends("parse_method", "single_dns")
	o.description = translate("Custom DNS Server (support: IP:Port or tls://IP:Port or https://IP/dns-query and other format).")

	o = s:option(ListValue, "upstreams_logic_mode", translate("Defines the upstreams logic mode"))
	o.description = translate(
    	"<ul>" ..
    	"<li>" .. translate("Defines the upstreams logic mode, possible values: load_balance, parallel, fastest_addr (default: load_balance).") .. "</li>" ..
    	"<li>" .. translate("When two or more DNS servers are deployed, enable this function.") .. "</li>" ..
    	"</ul>"
	)
	o:value("load_balance", translate("load_balance"))
	o:value("parallel", translate("parallel"))
	o:value("fastest_addr", translate("fastest_addr"))
	o:depends("parse_method", "parse_file")
	o.rmempty = true
	o.default = "load_balance"

	o = s:option(Flag, "dnsproxy_ipv6", translate("Disable IPv6 query mode"))
	o.description = translate("When disabled, all AAAA requests are not resolved.")
	o:depends("parse_method", "single_dns")
	o:depends("parse_method", "parse_file")
	o.rmempty = false
	o.default = "1"
end

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
	o:value("", translate("Disable ChinaDNS-NG"))
	o:value("wan", translate("Use DNS from WAN"))
	o:value("wan_114", translate("Use DNS from WAN and 114DNS"))
	o:value("114.114.114.114:53", translate("Nanjing Xinfeng 114DNS (114.114.114.114)"))
	o:value("119.29.29.29:53", translate("DNSPod Public DNS (119.29.29.29)"))
	o:value("223.5.5.5:53", translate("AliYun Public DNS (223.5.5.5)"))
	o:value("180.76.76.76:53", translate("Baidu Public DNS (180.76.76.76)"))
	o:value("101.226.4.6:53", translate("360 Security DNS (China Telecom) (101.226.4.6)"))
	o:value("123.125.81.6:53", translate("360 Security DNS (China Unicom) (123.125.81.6)"))
	o:value("1.2.4.8:53", translate("CNNIC SDNS (1.2.4.8)"))
	o:depends({pdnsd_enable = "1", run_mode = "router"})
	o:depends({pdnsd_enable = "2", run_mode = "router"})
	o:depends({pdnsd_enable = "3", run_mode = "router"})
	o:depends({pdnsd_enable = "5", run_mode = "router"})
	o:depends({pdnsd_enable = "6", run_mode = "router"})
	o.description = translate("Custom DNS Server format as IP:PORT (default: disabled)")
	o.validate = function(self, value, section)
		if (section and value) then
			if value == "wan" or value == "wan_114" then
				return value
			end

			if validation.ip4addrport(value) then
				return value
			end

			return nil, translate("Expecting: %s"):format(translate("valid address:port"))
		end

		return value
	end
end

return m

