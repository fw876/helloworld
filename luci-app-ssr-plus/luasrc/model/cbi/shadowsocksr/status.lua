-- Copyright (C) 2017 yushi studio <ywb94@qq.com>
-- Licensed to the public under the GNU General Public License v3.
require "nixio.fs"
require "luci.sys"
require "luci.model.uci"
local m, s, o
local redir_run = 0
local reudp_run = 0
local sock5_run = 0
local http_run = 0
local server_run = 0
local kcptun_run = 0
local tunnel_run = 0
local gfw_count = 0
local ad_count = 0
local ip_count = 0
local Process_list = luci.sys.exec("busybox ps -w 2>/dev/null || busybox ps")
local uci = require "luci.model.uci".cursor()
local global_server = uci:get_first("shadowsocksr", "global", "global_server", "nil")
local global_type = global_server ~= "nil" and (uci:get("shadowsocksr", global_server, "type") or "") or ""
local global_socks_enabled = uci:get_first("shadowsocksr", "socks5_proxy", "enabled", "0") == "1"
local global_socks_server = uci:get_first("shadowsocksr", "socks5_proxy", "server", "nil")
local global_http_enabled = uci:get_first("shadowsocksr", "http_proxy", "enabled", "0") == "1"
local has_3proxy = nixio.fs.access("/usr/bin/3proxy") or nixio.fs.access("/usr/libexec/3proxy") or nixio.fs.access("/bin/3proxy")
local pdnsd_mode = uci:get_first("shadowsocksr", 'global', 'pdnsd_enable', '0')
-- html constants
font_blue = [[<b style=color:green>]]
style_blue = [[<b style=color:red>]]
font_off = [[</b>]]
bold_on = [[<strong>]]
bold_off = [[</strong>]]
local kcptun_version = translate("Unknown")
local kcp_file = "/usr/bin/kcptun-client"
if not nixio.fs.access(kcp_file) then
	kcptun_version = translate("Not exist")
else
	if not nixio.fs.access(kcp_file, "rwx", "rx", "rx") then
		nixio.fs.chmod(kcp_file, 755)
	end
	kcptun_version = "<b>" ..luci.sys.exec(kcp_file .. " -v | awk '{printf $3}'") .. "</b>"
	if not kcptun_version or kcptun_version == "" then
		kcptun_version = translate("Unknown")
	end
end

if nixio.fs.access("/etc/ssrplus/gfw_list.conf") then
	gfw_count = tonumber(luci.sys.exec("cat /etc/ssrplus/gfw_list.conf | wc -l")) / 2
end

if nixio.fs.access("/etc/ssrplus/ad.conf") then
	ad_count = tonumber(luci.sys.exec("cat /etc/ssrplus/ad.conf | wc -l"))
end

if nixio.fs.access("/etc/ssrplus/china_ssr.txt") then
	ip_count = tonumber(luci.sys.exec("cat /etc/ssrplus/china_ssr.txt | wc -l"))
end

if nixio.fs.access("/etc/ssrplus/applechina.conf") then
	apple_count = tonumber(luci.sys.exec("cat /etc/ssrplus/applechina.conf | wc -l"))
end

if Process_list:find("udp.only.ssr.reudp") then
	reudp_run = 1
end

--[[
if Process_list:find("tcp.udp.dual.ssr.retcp") then
	redir_run = 1
end
]]--

if Process_list:find("tcp.only.ssr.retcp") then
	redir_run = 1
end

if Process_list:find("tcp.udp.ssr.local") then
	sock5_run = 1
end

if has_3proxy and Process_list:find("3proxy%-ssr%-http%.cfg") then
	http_run = 1
end

if Process_list:find("tcp.udp.ssr.retcp") then
	redir_run = 1
	reudp_run = 1
end

--[[
if Process_list:find("nft.ssr.retcp") then
	redir_run = 1
end
]]--

if Process_list:find("local.ssr.retcp") then
	redir_run = 1
	sock5_run = 1
end

--[[
if Process_list:find("local.nft.ssr.retcp") then
	redir_run = 1
	sock5_run = 1
end
]]--

if Process_list:find("local.udp.ssr.retcp") then
	reudp_run = 1
	redir_run = 1
	sock5_run = 1
end

if global_type == "socks5" and Process_list:find("ipt2socks") then
	if Process_list:find("%-T") or Process_list:find("%-%-tcp%-only") then
		redir_run = 1
	end
	if Process_list:find("%-U") or Process_list:find("%-%-udp%-only") then
		reudp_run = 1
	end
	if global_socks_enabled and (global_socks_server == "same" or global_socks_server == global_server) then
		sock5_run = 1
	end
end

if (global_type == "clash" or global_type == "v2ray" or global_type == "tuic" or global_type == "ss" or global_type == "ss-rust")
	and Process_list:find("ssr%-retcp") then
	redir_run = 1
	reudp_run = 1
	if global_socks_enabled and (global_socks_server == "same" or global_socks_server == global_server) then
		sock5_run = 1
	end
end

if (global_type == "clash" or global_type == "v2ray" or global_type == "tuic" or global_type == "ss" or global_type == "ss-rust")
	and Process_list:find("mihomo")
	and (Process_list:find("/clash%-") or Process_list:find("/v2ray%-") or Process_list:find("/tuic%-") or Process_list:find("/ss%-")) then
	redir_run = 1
	reudp_run = 1
	if global_socks_enabled and (global_socks_server == "same" or global_socks_server == global_server) then
		sock5_run = 1
	end
end

if has_3proxy and global_http_enabled and http_run == 0 and Process_list:find("3proxy%-ssr%-http%.cfg") then
	http_run = 1
end

if Process_list:find("kcptun.client") then
	kcptun_run = 1
end

if Process_list:find("ssr.server") then
	server_run = 1
end

if Process_list:find("mihomo") and Process_list:find("/ss%-server%-") then
	server_run = 1
end

if  Process_list:find("ssrplus/bin/dns2tcp") or
    Process_list:find("ssrplus/bin/mosdns") or
    Process_list:find("chinadns.*127.0.0.1.*5335") then
	pdnsd_run = 1
end

if pdnsd_mode == "7" and (global_type == "clash" or global_type == "v2ray" or global_type == "tuic" or global_type == "ss") and Process_list:find("ssr%-retcp") then
	pdnsd_run = 1
end

if pdnsd_mode == "7" and global_type == "v2ray" and Process_list:find("ssr%-retcp%.json") then
	pdnsd_run = 1
end

m = SimpleForm("Version")
m.reset = false
m.submit = false

s = m:field(DummyValue, "redir_run", translate("Global Client"))
s.rawhtml = true
if redir_run == 1 then
	s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
else
	s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
end

s = m:field(DummyValue, "reudp_run", translate("Game Mode UDP Relay"))
s.rawhtml = true
if reudp_run == 1 then
	s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
else
	s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
end

if uci:get_first("shadowsocksr", 'global', 'pdnsd_enable', '0') ~= '0' then
	s = m:field(DummyValue, "pdnsd_run", translate("DNS Anti-pollution"))
	s.rawhtml = true
	if pdnsd_run == 1 then
		s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
	else
		s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
	end
end

s = m:field(DummyValue, "sock5_run", translate("Global SOCKS5 Proxy Server"))
s.rawhtml = true
if sock5_run == 1 then
	s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
else
	s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
end

if has_3proxy then
	s = m:field(DummyValue, "http_run", translate("Global HTTP/HTTPS Proxy Server"))
	s.rawhtml = true
	if http_run == 1 then
		s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
	else
		s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
	end
end

s = m:field(DummyValue, "server_run", translate("Local Servers"))
s.rawhtml = true
if server_run == 1 then
	s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
else
	s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
end

if nixio.fs.access("/usr/bin/kcptun-client") then
	s = m:field(DummyValue, "kcp_version", translate("KcpTun Version"))
	s.rawhtml = true
	s.value = kcptun_version
	s = m:field(DummyValue, "kcptun_run", translate("KcpTun"))
	s.rawhtml = true
	if kcptun_run == 1 then
		s.value = font_blue .. bold_on .. translate("Running") .. bold_off .. font_off
	else
		s.value = style_blue .. bold_on .. translate("Not Running") .. bold_off .. font_off
	end
end

s = m:field(Button, "Restart", translate("Restart ShadowSocksR Plus+"))
s.inputtitle = translate("Restart Service")
s.inputstyle = "reload"
s.write = function()
	luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "client"))
end

s = m:field(DummyValue, "google", translate("Google Connectivity"))
s.value = translate("No Check")
s.template = "shadowsocksr/check"

s = m:field(DummyValue, "baidu", translate("Baidu Connectivity"))
s.value = translate("No Check")
s.template = "shadowsocksr/check"

s = m:field(DummyValue, "gfw_data", translate("GFW List Data"))
s.rawhtml = true
s.template = "shadowsocksr/refresh"
s.value = gfw_count .. " " .. translate("Records")

s = m:field(DummyValue, "ip_data", translate("China IP Data"))
s.rawhtml = true
s.template = "shadowsocksr/refresh"
s.value = ip_count .. " " .. translate("Records")

if uci:get_first("shadowsocksr", 'global', 'apple_optimization', '0') ~= '0' then
	s = m:field(DummyValue, "apple_data", translate("Apple Domains Data"))
	s.rawhtml = true
	s.template = "shadowsocksr/refresh"
	s.value = apple_count .. " " .. translate("Records")
end

if uci:get_first("shadowsocksr", 'global', 'adblock', '0') == '1' then
	s = m:field(DummyValue, "ad_data", translate("Advertising Data"))
	s.rawhtml = true
	s.template = "shadowsocksr/refresh"
	s.value = ad_count .. " " .. translate("Records")
end

s = m:field(DummyValue, "check_port", translate("Check Server Port"))
s.template = "shadowsocksr/checkport"
s.value = translate("No Check")

return m
