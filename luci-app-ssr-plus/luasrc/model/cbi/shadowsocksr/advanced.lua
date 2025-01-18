local m, s, o
local uci = luci.model.uci.cursor()
local server_table = {}
local type_table = {}
local function is_finded(e)
	return luci.sys.exec('type -t -p "%s"' % e) ~= "" and true or false
end

uci:foreach("shadowsocksr", "servers", function(s)
	if s.alias then
		server_table[s[".name"]] = "[%s]:%s" % {string.upper(s.v2ray_protocol or s.type), s.alias}
	elseif s.server and s.server_port then
		server_table[s[".name"]] = "[%s]:%s:%s" % {string.upper(s.v2ray_protocol or s.type), s.server, s.server_port}
	end
	if s.type then
		type_table[s[".name"]] = s.type
	end
end)

local key_table = {}
for key, _ in pairs(server_table) do
	table.insert(key_table, key)
end

table.sort(key_table)

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

o = s:option(Flag, "netflix_enable", translate("Enable Netflix Mode"))
o.rmempty = false

o = s:option(Value, "nfip_url", translate("nfip_url"))
o:value("https://fastly.jsdelivr.net/gh/QiuSimons/Netflix_IP/NF_only.txt", translate("Netflix IP Only"))
o:value("https://fastly.jsdelivr.net/gh/QiuSimons/Netflix_IP/getflix.txt", translate("Netflix and AWS"))
o.default = "https://fastly.jsdelivr.net/gh/QiuSimons/Netflix_IP/NF_only.txt"
o.description = translate("Customize Netflix IP Url")
o:depends("netflix_enable", "1")

o = s:option(ListValue, "shunt_dns_mode", translate("DNS Query Mode For Shunt Mode"))
o:value("1", translate("Use DNS2SOCKS query and cache"))
if is_finded("mosdns") then
o:value("2", translate("Use MOSDNS query"))
end
o:depends("netflix_enable", "1")
o.default = 1

o = s:option(Value, "shunt_dnsserver", translate("Anti-pollution DNS Server For Shunt Mode"))
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
o:depends("shunt_dns_mode", "1")
o.description = translate("Custom DNS Server format as IP:PORT (default: 8.8.4.4:53)")
o.datatype = "ip4addrport"

o = s:option(ListValue, "shunt_mosdns_dnsserver", translate("Anti-pollution DNS Server"))
o:value("tcp://8.8.4.4:53,tcp://8.8.8.8:53", translate("Google Public DNS"))
o:value("tcp://208.67.222.222:53,tcp://208.67.220.220:53", translate("OpenDNS"))
o:value("tcp://209.244.0.3:53,tcp://209.244.0.4:53", translate("Level 3 Public DNS-1 (209.244.0.3-4)"))
o:value("tcp://4.2.2.1:53,tcp://4.2.2.2:53", translate("Level 3 Public DNS-2 (4.2.2.1-2)"))
o:value("tcp://4.2.2.3:53,tcp://4.2.2.4:53", translate("Level 3 Public DNS-3 (4.2.2.3-4)"))
o:value("tcp://1.1.1.1:53,tcp://1.0.0.1:53", translate("Cloudflare DNS"))
o:depends("shunt_dns_mode", "2")
o.description = translate("Custom DNS Server for mosdns")

o = s:option(Flag, "shunt_mosdns_ipv6", translate("Disable IPv6 In MOSDNS Query Mode (Shunt Mode)"))
o:depends("shunt_dns_mode", "2")
o.rmempty = false
o.default = "0"

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
o:value("https://raw.githubusercontent.com/neodevpro/neodevhost/master/lite_dnsmasq.conf", translate("NEO DEV HOST Lite"))
o:value("https://raw.githubusercontent.com/neodevpro/neodevhost/master/dnsmasq.conf", translate("NEO DEV HOST Full"))
o:value("https://anti-ad.net/anti-ad-for-dnsmasq.conf", translate("anti-AD"))
o.default = "https://raw.githubusercontent.com/neodevpro/neodevhost/master/lite_dnsmasq.conf"
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

-- Enable/Disable Option
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 0
o.rmempty = false

-- Server Selection
o = s:option(ListValue, "server", translate("Server"))
o:value("same", translate("Same as Global Server"))
for _, key in pairs(key_table) do
    o:value(key, server_table[key])
end
o.default = "same"
o.rmempty = false

-- Dynamic value handling based on enabled/disabled state
o.cfgvalue = function(self, section)
    local enabled = m:get(section, "enabled")
    if enabled == "0" then
        return m:get(section, "old_server") or "same"
    end
    return Value.cfgvalue(self, section) or "same" -- Default to `same` when enabled
end

o.write = function(self, section, value)
    local enabled = m:get(section, "enabled")
    if enabled == "0" then
        local old_server = Value.cfgvalue(self, section) or "same"
        if old_server ~= "nil" then
            m:set(section, "old_server", old_server)
        end
        m:set(section, "server", "nil")
    else
        m:del(section, "old_server")
        -- Write the value normally when enabled
        Value.write(self, section, value)
    end
end

-- Socks Auth
if is_finded("xray") then
o = s:option(ListValue, "socks5_auth", translate("Socks5 Auth Mode"), translate("Socks protocol auth methods, default:noauth."))
o.default = "noauth"
o:value("noauth", "NOAUTH")
o:value("password", "PASSWORD")
o.rmempty = true
for key, server_type in pairs(type_table) do
    if server_type == "v2ray" then
        -- 如果服务器类型是 v2ray，则设置依赖项显示
        o:depends("server", key)
    end
end

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
for key, server_type in pairs(type_table) do
    if server_type == "v2ray" then
        -- 如果服务器类型是 v2ray，则设置依赖项显示
        o:depends("server", key)
    end
end
end

-- Local Port
o = s:option(Value, "local_port", translate("Local Port"))
o.datatype = "port"
o.default = 1080
o.rmempty = false

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

o = s:option(Value, "fragment_length", translate("Fragment Length"), translate("Fragmented packet length (byte)"))
o.default = "100-200"
o:depends("fragment", true)

o = s:option(Value, "fragment_interval", translate("Fragment Interval"), translate("Fragmentation interval (ms)"))
o.default = "10-20"
o:depends("fragment", true)

o = s:option(Flag, "noise", translate("Noise"), translate("UDP noise, Under some circumstances it can bypass some UDP based protocol restrictions."))
o.default = 0

s = m:section(TypedSection, "xray_noise_packets", translate("Xray Noise Packets"))
s.description = translate(
    "<font style='color:red'>" .. translate("To send noise packets, select \"Noise\" in Xray Settings.") .. "</font>" ..
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
o:value("base64", "base64")

o = s:option(Value, "domainStrategy", translate("Domain Strategy"))
o.default = "UseIP"
o:value("AsIs", "AsIs")
o:value("UseIP", "UseIP")
o:value("UseIPv4", "UseIPv4")
o:value("ForceIP", "ForceIP")
o:value("ForceIPv4", "ForceIPv4")
o.rmempty = false

o = s:option(Value, "packet", translate("Packet"))
o.datatype = "minlength(1)"
o.rmempty = false

o = s:option(Value, "delay", translate("Delay (ms)"))
o.datatype = "or(uinteger,portrange)"
o.rmempty = false
end

return m
