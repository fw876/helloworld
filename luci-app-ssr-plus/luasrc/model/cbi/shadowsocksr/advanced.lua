local m, s, o
local cbi = require "luci.cbi"
local uci = require "luci.model.uci".cursor()
local URL = require "url"

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
local server_table = {}
local type_table = {}
local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" -p "/usr/libexec/%s" 2>/dev/null', e, e)) ~= ""
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

uci:foreach("shadowsocksr", "servers", function(s)
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
	if s.type and s.type ~= "tun" then
		type_table[s[".name"]] = s.type
	end
end)

local key_table = {}
for key, _ in pairs(server_table) do
	table.insert(key_table, key)
end

table.sort(key_table)

-- 获取 Xray 版本号
if is_finded("xray") then
	local version = luci.sys.exec("xray version 2>&1")
	if version and version ~= "" then
		xray_version = version:match("Xray%s+([%d%.]+)")
	end
end

-- 将 Xray 版本号转换为数字
if xray_version and xray_version ~= "" then
	local major, minor, patch =
		xray_version:match("(%d+)%.?(%d*)%.?(%d*)")

	major = tonumber(major) or 0
	minor = tonumber(minor) or 0
	patch = tonumber(patch) or 0

	xray_version_val = major * 10000 + minor * 100 + patch
end

m = Map("shadowsocksr")
-- [[ global ]]--
s = m:section(TypedSection, "global", translate("Server failsafe auto swith and custom update settings"))
s.anonymous = true

-- o = s:option(Flag, "monitor_enable", translate("Enable Process Deamon"))
-- o.rmempty = false
-- o.default = "1"

o = s:option(Flag, "enable_switch", translate("Enable Auto Switch"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "switch_time", translate("Switch check cycly(second)"))
o.datatype = "uinteger"
o:depends("enable_switch", "1")
o.default = 667

o = s:option(Value, "switch_timeout", translate("Check timout(second)"))
o.datatype = "uinteger"
o:depends("enable_switch", "1")
o.default = 5

o = s:option(Value, "switch_try_count", translate("Check Try Count"))
o.datatype = "uinteger"
o:depends("enable_switch", "1")
o.default = 3

s:append(cbi.Template("shadowsocksr/advanced_switch_compact"))

o = s:option(Value, "default_node_local_port", translate("Default Node Local Port"))
o.datatype = "port"
o.default = 1234
o.rmempty = false

o = s:option(Value, "gfwlist_url", translate("gfwlist Update url"))
o:value("https://fastly.jsdelivr.net/gh/YW5vbnltb3Vz/domain-list-community@release/gfwlist.txt", translate("v2fly/domain-list-community"))
o:value("https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt", translate("Loyalsoldier/v2ray-rules-dat"))
o:value("https://fastly.jsdelivr.net/gh/Loukky/gfwlist-by-loukky/gfwlist.txt", translate("Loukky/gfwlist-by-loukky"))
o:value("https://fastly.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt", translate("gfwlist/gfwlist"))
o.default = "https://fastly.jsdelivr.net/gh/YW5vbnltb3Vz/domain-list-community@release/gfwlist.txt"

o = s:option(Value, "chnroute_url", translate("Chnroute Update url"))
o:value("https://ispip.clang.cn/all_cn.txt", translate("Clang.CN"))
o:value("https://ispip.clang.cn/all_cn_cidr.txt", translate("Clang.CN.CIDR"))
o:value("https://fastly.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt", translate("china-operator-ip"))
o.default = "https://ispip.clang.cn/all_cn.txt"

o = s:option(Flag, "apple_optimization", translate("Apple domains optimization"), translate("For Apple domains equipped with Chinese mainland CDN, always responsive to Chinese CDN IP addresses"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "apple_url", translate("Apple Domains Update url"))
o:value("https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf", translate("felixonmars/dnsmasq-china-list"))
o.default = "https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf"
o:depends("apple_optimization", "1")

o = s:option(Value, "apple_dns", translate("Apple Domains DNS"), translate("If empty, Not change Apple domains parsing DNS (Default is empty)"))
o.rmempty = true
o.default = ""
o.datatype = "ip4addr"
o:depends("apple_optimization", "1")

o = s:option(Flag, "adblock", translate("Enable adblock"))
o.rmempty = false

o = s:option(Value, "adblock_url", translate("adblock_url"))
o:value("https://raw.githubusercontent.com/neodevpro/neodevhost/master/dnsmasq.conf", translate("NEO DEV HOST"))
o:value("https://anti-ad.net/anti-ad-for-dnsmasq.conf", translate("anti-AD"))
o.default = "https://raw.githubusercontent.com/neodevpro/neodevhost/master/dnsmasq.conf"
o:depends("adblock", "1")
o.description = translate("Support AdGuardHome and DNSMASQ format list")

o = s:option(Button, "Reset", translate("Reset to defaults"))
o.inputstyle = "reload"
o.write = function()
	luci.sys.call("/etc/init.d/shadowsocksr reset")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers"))
end

-- [[ SOCKS5 Proxy ]]--
s = m:section(TypedSection, "socks5_proxy", translate("Global SOCKS5 Proxy Server"))
s.anonymous = true
-- s.description = translate("Only Same as Global Server is supported here. If the current main program supports a built-in SOCKS5 listener, it will be enabled in-process; otherwise SSR Plus will fall back to microsocks.")

-- Enable/Disable Option
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 0
o.rmempty = false

-- Socks Auth
if is_finded("xray") then
o = s:option(ListValue, "socks5_auth", translate("Socks5 Auth Mode"), translate("Socks protocol auth methods, default:noauth."))
o.default = "noauth"
o:value("noauth", "NOAUTH")
o:value("password", "PASSWORD")
o.rmempty = true

-- Socks User
o = s:option(Value, "socks5_user", translate("Socks5 User"), translate("Only when Socks5 Auth Mode is password valid, Mandatory."))
o.rmempty = true
o:depends("socks5_auth", "password")

-- Socks Password
o = s:option(Value, "socks5_pass", translate("Socks5 Password"), translate("Only when Socks5 Auth Mode is password valid, Not mandatory."))
o.password = true
o.rmempty = true
o:depends("socks5_auth", "password")

-- Socks Mixed
o = s:option(Flag, "socks5_mixed", translate("Enabled Mixed"), translate("Mixed as an alias of socks, default:Enabled."))
o.default = "1"
o.rmempty = false
end

-- Local Port
o = s:option(Value, "local_port", translate("Local Port"))
o.datatype = "port"
o.default = 1080
o.rmempty = false

if is_finded("3proxy") then
	-- [[ HTTP/HTTPS Proxy ]]--
	s = m:section(TypedSection, "http_proxy", translate("Global HTTP/HTTPS Proxy Server"))
	s.anonymous = true
	-- s.description = translate("Only Same as Global Server is supported here. HTTP/HTTPS proxy service is provided through 3proxy.")

	o = s:option(Flag, "enabled", translate("Enable"))
	o.default = 0
	o.rmempty = false

	o = s:option(ListValue, "http_auth", translate("HTTP Auth Mode"), translate("HTTP proxy auth method, default:none."))
	o.default = "none"
	o:value("none", "NONE")
	o:value("password", "PASSWORD")
	o.rmempty = false

	o = s:option(Value, "http_user", translate("HTTP User"), translate("Only when HTTP Auth Mode is password valid, Mandatory."))
	o.rmempty = true
	o:depends("http_auth", "password")

	o = s:option(Value, "http_pass", translate("HTTP Password"), translate("Only when HTTP Auth Mode is password valid, Not mandatory."))
	o.password = true
	o.rmempty = true
	o:depends("http_auth", "password")

	o = s:option(Value, "local_port", translate("Local Port"))
	o.datatype = "port"
	o.default = 3128
	o.rmempty = false
end

-- [[ fragmen Settings ]]--
if is_finded("xray") then
	s = m:section(TypedSection, "global_xray_fragment", translate("Xray Fragment Settings"))
	s.anonymous = true

	o = s:option(Flag, "fragment", translate("Fragment"), translate("TCP fragments, which can deceive the censorship system in some cases, such as bypassing SNI blacklists."))
	o.default = 0

	o = s:option(ListValue, "fragment_packets", translate("Fragment Packets"), translate("\"1-3\" is for segmentation at TCP layer, applying to the beginning 1 to 3 data writes by the client. \"tlshello\" is for TLS client hello packet fragmentation."))
	o.default = "tlshello"
	o:value("tlshello", "tlshello")
	o:value("1-1", "1-1")
	o:value("1-2", "1-2")
	o:value("1-3", "1-3")
	o:value("1-5", "1-5")
	o:depends("fragment", true)

	o = s:option(Value, "fragment_length", translate("Fragment Length"))
	if xray_version_val <= 260601 then
		o.datatype = "or(uinteger,portrange)"
		o.default = "100-200"
	else
		o.default = "3-5,6-8,10-20"
	end
	o:depends("fragment", true)
	o.description = translate(
    	"<ul>" ..
    	"<li>" .. translate("Fragmented packet length (byte)") .. "</li>" .. 
    	"<li>" .. translate("Note: When version is higher than 26.6.1, input multiple fragment lengths saperate with ','.") .. "</li>" ..
    	"</ul>"
	)

	o = s:option(Value, "fragment_delay", translate("Fragment Delay"))
	if xray_version_val <= 260601 then
		o.datatype = "or(uinteger,portrange)"
		o.default = "10-20"
	else
		o.default = "1-2,5-6,10-20"
	end
	o:depends("fragment", true)
	o.description = translate(
    	"<ul>" ..
    	"<li>" .. translate("Fragmentation interval (ms)") .. "</li>" .. 
    	"<li>" .. translate("Note: When version is higher than 26.6.1, input multiple fragment intervals saperate with ','.") .. "</li>" ..
    	"</ul>"
	)

	o = s:option(Value, "fragment_maxSplit", translate("Max Split"), translate("Limit the maximum number of splits."))
	o.datatype = "or(uinteger,portrange)"
	if xray_version_val <= 260601 then
		o.datatype = "or(uinteger,portrange)"
		o.default = "100-200"
	else
		o.default = "3-6"
	end
	o:depends("fragment", true)

	o = s:option(Flag, "noise", translate("Noise"), translate("UDP noise, Under some circumstances it can bypass some UDP based protocol restrictions."))
	o.default = 0

	s = m:section(TypedSection, "xray_noise_packets", translate("Xray Noise Packets"))
	s.description = translate(
		"<font style='color:red'>" .. translate("To send noise packets, select \"Noise\" in Xray Settings.") .. "</font>" ..
		"<br/><font><b>" .. translate("Packet or Rand length as a string, e.g., 10-20.") .. "</b></font>" ..
		"<br/><font><b>" .. translate("For specific usage, see:") .. "</b></font>" ..
		"<a href='https://xtls.github.io/config/outbounds/freedom.html' target='_blank'>" ..
		"<font style='color:green'><b>" .. translate("Click to the page") .. "</b></font></a>")
	s.template = "cbi/tblsection"
	s.sortable = true
	s.anonymous = true
	s.addremove = true

	s.remove = function(self, section)
		for k, v in pairs(self.children) do
			v.rmempty = true
			v.validate = nil
		end
		TypedSection.remove(self, section)
	end

	o = s:option(Flag, "enabled", translate("Enable"))
	o.default = 1
	o.rmempty = false

	o = s:option(ListValue, "type", translate("Type"))
	o.default = "base64"
	o:value("rand", "rand")
	o:value("str", "str")
	o:value("hex", "hex")
	o:value("base64", "base64")

	o = s:option(Value, "domainStrategy", translate("Domain Strategy"))
	o.default = "AsIs"
	o:value("AsIs", "AsIs")
	o:value("UseIP", "UseIP")
	o:value("UseIPv4", "UseIPv4")
	o:value("ForceIP", "ForceIP")
	o:value("ForceIPv4", "ForceIPv4")
	o.rmempty = false

	o = s:option(Value, "packet", translate("Packet | Rand Length"))
	o.datatype = "minlength(1)"
	o.rmempty = false

	o = s:option(Value, "delay", translate("Delay (ms)"))
	o.datatype = "or(uinteger,portrange)"
	o.rmempty = false
	
	s:append(cbi.Template("shadowsocksr/optimize_cbi_ui"))
end

return m
