-- Licensed to the public under the GNU General Public License v3.
require "luci.http"
require "luci.sys"
require "nixio.fs"
require "luci.dispatcher"
require "luci.model.uci"
local cbi = require "luci.cbi"
local uci = require "luci.model.uci".cursor()

local m, s, o, node
local server_count = 0

-- 确保正确判断程序是否存在
local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" 2>/dev/null', e)) ~= ""
end

local function is_js_luci()
	return luci.sys.call('[ -f "/www/luci-static/resources/uci.js" ]') == 0
end

local function url(...)
	local url = string.format("admin/services/%s", "shadowsocksr")
	local args = { ... }
	for i, v in ipairs(args) do
		if v and v ~= "" then
			url = url .. "/" .. v
		end
	end
	return require "luci.dispatcher".build_url(url)
end

-- 默认的保存并应用行为
local function apply_redirect(m)
	local tmp_uci_file = "/etc/config/" .. "shadowsocksr" .. "_redirect"
	if m.redirect and m.redirect ~= "" then
		if nixio.fs.access(tmp_uci_file) then
			local redirect
			for line in io.lines(tmp_uci_file) do
				redirect = line:match("option%s+url%s+['\"]([^'\"]+)['\"]")
				if redirect and redirect ~= "" then break end
			end
			if redirect and redirect ~= "" then
				luci.sys.call("/bin/rm -f " .. tmp_uci_file)
				luci.http.redirect(redirect)
			end
		else
			nixio.fs.writefile(tmp_uci_file, "config redirect\n")
		end
		m.on_after_save = function(self)
			local redirect = self.redirect
			if redirect and redirect ~= "" then
				m.uci:set("shadowsocksr" .. "_redirect", "@redirect[0]", "url", redirect)
			end
		end
	else
		luci.sys.call("/bin/rm -f " .. tmp_uci_file)
	end
end

local function set_apply_on_parse(map)
	if not map then return end
	if is_js_luci() then
		apply_redirect(map)
		local old = map.on_after_save
		map.on_after_save = function(self)
			if old then old(self) end
			map:set("@global[0]", "timestamp", os.time())
		end
	end
end

local has_xray = is_finded("xray")
local has_hysteria2 = is_finded("hysteria")

local hy2_type_list = {}

if has_hysteria2 then
	table.insert(hy2_type_list, { id = "hysteria2", name = translate("Hysteria2") })
end
if has_xray then
	table.insert(hy2_type_list, { id = "v2ray", name = translate("Xray (Hysteria2)") })
end

-- 如果用户没有手动设置，则自动选择
if not xray_hy2_type or xray_hy2_type == "" then
	if has_hysteria2 then
		xray_hy2_type = "hysteria2"
	elseif has_xray then
		xray_hy2_type = "v2ray"
	end
end

local has_ss_rust = is_finded("sslocal") or is_finded("ssserver")
local has_ss_libev = is_finded("ss-redir") or is_finded("ss-local")

local ss_type_list = {}

if has_ss_rust then
	table.insert(ss_type_list, { id = "ss-rust", name = translate("ShadowSocks-rust Version") })
end
if has_ss_libev then
	table.insert(ss_type_list, { id = "ss-libev", name = translate("ShadowSocks-libev Version") })
end
if has_xray then
	table.insert(ss_type_list, { id = "v2ray", name = translate("Xray (ShadowSocks)") })
end

-- 如果用户没有手动设置，则自动选择
if not ss_type or ss_type == "" then
	if has_ss_rust then
		ss_type = "ss-rust"
	elseif has_ss_libev then
		ss_type = "ss-libev"
	elseif has_xray then
		ss_type = "v2ray"
	end
end

uci:foreach("shadowsocksr", "servers", function(s)
	server_count = server_count + 1
end)

m = Map("shadowsocksr", translate("Servers subscription and manage"))

-- Server Subscribe
s = m:section(TypedSection, "server_subscribe")
s.anonymous = true

o = s:option(Flag, "auto_update", translate("Auto Update"))
o.rmempty = false
o.description = translate("Auto Update Server subscription, GFW list and CHN route")

o = s:option(ListValue, "auto_update_week_time", translate("Update cycle (Day/Week)"))
o:value('*', translate("Every Day"))
o:value("1", translate("Every Monday"))
o:value("2", translate("Every Tuesday"))
o:value("3", translate("Every Wednesday"))
o:value("4", translate("Every Thursday"))
o:value("5", translate("Every Friday"))
o:value("6", translate("Every Saturday"))
o:value("0", translate("Every Sunday"))
o.default = "*"
o.rmempty = true
o:depends("auto_update", "1")

o = s:option(ListValue, "auto_update_day_time", translate("Regular update (Hour)"))
for t = 0, 23 do
	o:value(t, t .. ":00")
end
o.default = 2
o.rmempty = true
o:depends("auto_update", "1")

o = s:option(ListValue, "auto_update_min_time", translate("Regular update (Min)"))
for i = 0, 59 do
	o:value(i, i .. ":00")
end
o.default = 30
o.rmempty = true
o:depends("auto_update", "1")

-- 确保 hy2_type_list 不为空
if #hy2_type_list > 0 then
	o = s:option(ListValue, "xray_hy2_type", string.format("<b><span style='color:red;'>%s</span></b>", translatef("%s Node Use Type", "Hysteria2")))
	o.description = translate("The configured type also applies to the core specified when manually importing nodes.")
	for _, v in ipairs(hy2_type_list) do
		o:value(v.id, v.name) -- 存储 "Xray" / "Hysteria2"，但 UI 显示完整名称
	end
	o.default = xray_hy2_type  -- 设置默认值
end

-- 确保 ss_type_list 不为空
if #ss_type_list > 0 then
	o = s:option(ListValue, "ss_type", string.format("<b><span style='color:red;'>%s</span></b>", translatef("%s Node Use Version", "ShadowSocks")))
	o.description = translate("Selection ShadowSocks Node Use Version.")
	for _, v in ipairs(ss_type_list) do
		o:value(v.id, v.name) -- 存储 "ss-libev" / "ss-rust"，但 UI 显示完整名称
	end
	o.default = ss_type  -- 设置默认值
end

o = s:option(DynamicList, "subscribe_url", translate("Subscribe URL"))
o.rmempty = true

o = s:option(Value, "filter_words", translate("Subscribe Filter Words"))
o.rmempty = true
o.description = translate("Filter Words splited by /")

o = s:option(Value, "save_words", translate("Subscribe Save Words"))
o.rmempty = true
o.description = translate("Save Words splited by /")

o = s:option(Button, "update_Sub", translate("Update Subscribe List"))
o.inputstyle = "reload"
o.description = translate("Update subscribe url list first")
o.write = function()
	uci:commit("shadowsocksr")
	luci.sys.exec("rm -rf /tmp/sub_md5_*")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers"))
end

o = s:option(Flag, "allow_insecure", translate("Allow subscribe Insecure nodes By default"))
o.rmempty = false
o.description = translate("Subscribe nodes allows insecure connection as TLS client (insecure)")
o.default = "0"

o = s:option(Flag, "switch", translate("Subscribe Default Auto-Switch"))
o.rmempty = false
o.description = translate("Subscribe new add server default Auto-Switch on")
o.default = "1"

o = s:option(Flag, "proxy", translate("Through proxy update"))
o.rmempty = false
o.description = translate("Through proxy update list, Not Recommended ")

o = s:option(Button, "subscribe", translate("Update All Subscribe Servers"))
o.rawhtml = true
o.template = "shadowsocksr/subscribe"

o = s:option(Button, "delete", translate("Delete All Subscribe Servers"))
o.inputstyle = "reset"
o.description = string.format(translate("Server Count") .. ": %d", server_count)
o.write = function()
	luci.http.redirect(url("delete"))
end

o = s:option(Value, "url_test_url", translate("URL Test Address"))
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o.default = o.keylist[3]


o = s:option(Value, "user_agent", translate("User-Agent"))
o.default = "v2rayN/9.99"
o:value("curl", "Curl")
o:value("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Linux")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Windows")
o:value("v2rayN/9.99", "v2rayN")

-- [[ Servers Manage ]]--
s = m:section(TypedSection, "servers")
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
set_apply_on_parse(m)
s.sortable = true
--[[
s.extedit = url("servers", "%s")
function s.create(self, ...)
    local sid = TypedSection.create(self, ...)
    if sid then
        local newsid = "cfg" .. sid:sub(-6)
		-- 删除匿名
		self.map.uci:delete(self.config, sid)
        -- 重命名 section
        self.map.uci:section(self.config, self.sectiontype, newsid)
        luci.http.redirect(self.extedit % newsid)
        return
    end
end
]]--

o = s:option(DummyValue, "type", translate("Type"))
function o.cfgvalue(self, section)
	return m:get(section, "v2ray_protocol") or Value.cfgvalue(self, section) or translate("None")
end

o = s:option(DummyValue, "alias", translate("Alias"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or translate("None")
end

o = s:option(DummyValue, "server_port", translate("Server Port"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "N/A"
end

o = s:option(DummyValue, "server_port", translate("Socket Connected"))
o.template = "shadowsocksr/socket"
o.width = "10%"
o.render = function(self, section, scope)
	local cfg = s:cfgvalue(section) or {}
	self.transport = cfg.transport
	self.type = cfg.type
	self.v2ray_protocol = cfg.v2ray_protocol
	if self.transport == 'ws' then
		self.ws_path = cfg.ws_path
		self.tls = cfg.tls
		self.tls_host = cfg.tls_host
	end
	DummyValue.render(self, section, scope)
end

o = s:option(DummyValue, "server", translate("Ping Latency"))
o.template = "shadowsocksr/ping"
o.width = "10%"

local global_server = uci:get_first('shadowsocksr', 'global', 'global_server') 

node = s:option(Button, "apply_node", translate("Apply"))
node.inputstyle = "apply"
node.render = function(self, section, scope)
	if section == global_server then
		self.title = translate("Reapply")
	else
		self.title = translate("Apply")
	end
	Button.render(self, section, scope)
end
node.write = function(self, section)
	uci:set("shadowsocksr", '@global[0]', 'global_server', section)
	uci:save("shadowsocksr")
	uci:commit("shadowsocksr")
	luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
	luci.http.redirect(url("restart"))
end

o = s:option(Flag, "switch_enable", translate("Auto Switch"))
o.rmempty = false
function o.cfgvalue(...)
	return Value.cfgvalue(...) or 1
end

m:append(cbi.Template("shadowsocksr/server_list"))

return m
