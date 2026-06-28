-- Licensed to the public under the GNU General Public License v3.
require "luci.http"
require "luci.sys"
require "luci.util"
require "nixio.fs"
require "luci.dispatcher"
require "luci.model.uci"
local nixio = require "nixio"
local json = require "luci.jsonc"
local cbi = require "luci.cbi"
local uci = require "luci.model.uci".cursor()
local URL = require "url"

local m, s, o, node
local server_count = 0
local server_cache = {}
local server_sections = {}
local detect_cache = {}
local CLASH_YAML_DIR = "/etc/ssrplus/clash"
local CLASH_YAML_HELPER = "/usr/share/shadowsocksr/clash_yaml.lua"
local DEFAULT_SERVER_PAGE_SIZE = 50
local SERVER_PAGE_SIZE_OPTIONS = {25, 50, 100, 200, 0}

local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" -p "/usr/libexec/%s" 2>/dev/null', e, e)) ~= ""
end

local function is_js_luci()
	return luci.sys.call('[ -f "/www/luci-static/resources/uci.js" ]') == 0
end

-- 保存并应用行为
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
			-- map:set("@global[0]", "timestamp", os.time())
		end
	end
end

local function trim(text)
	if not text or text == "" then
		return ""
	end
	return (text:gsub("^%s*(.-)%s*$", "%1"))
end

local function parse_nonnegative_int(value)
	local number = tonumber(value)
	if not number then
		return nil
	end
	number = math.floor(number)
	if number < 0 then
		return nil
	end
	return number
end

local function in_list(list, target)
	for _, item in ipairs(list) do
		if item == target then
			return true
		end
	end
	return false
end

local function upload_alias(filename)
	local stem = tostring(filename or ""):gsub("\\", "/"):match("([^/]+)$") or "custom"
	stem = stem:gsub("%.%w+$", "")
	stem = trim(stem):gsub("[%c\r\n]+", " "):gsub("%s+", " ")
	if stem == "" then
		stem = "custom"
	end
	return "Clash_" .. stem
end

local function hash_file(path)
	local cmd = "md5sum " .. luci.util.shellquote(path) .. " 2>/dev/null | awk '{print $1}'"
	return trim(luci.sys.exec(cmd))
end

local function preprocess_clash_yaml(input_path, output_path)
	local cmd = string.format(
		"/usr/bin/lua %s prepare %s %s >/dev/null 2>&1",
		luci.util.shellquote(CLASH_YAML_HELPER),
		luci.util.shellquote(input_path),
		luci.util.shellquote(output_path)
	)
	return luci.sys.call(cmd) == 0
end

local function clash_path_in_use(path, exclude_sid)
	local in_use = false

	uci:foreach("shadowsocksr", "servers", function(section)
		if section[".name"] ~= exclude_sid and section.clash_path == path then
			in_use = true
			return false
		end
	end)

	return in_use
end

local function cleanup_old_clash_path(old_path, new_path, sid)
	if not old_path or old_path == "" or old_path == new_path then
		return
	end
	if old_path:sub(1, #CLASH_YAML_DIR + 1) ~= CLASH_YAML_DIR .. "/" then
		return
	end
	if clash_path_in_use(old_path, sid) then
		return
	end
	nixio.fs.remove(old_path)
end

local function find_uploaded_clash_section(upload_name, final_path)
	local sid

	uci:foreach("shadowsocksr", "servers", function(section)
		if section.type ~= "clash" or section.yaml_upload ~= "1" then
			return
		end
		if upload_name ~= "" and section.yaml_upload_name == upload_name then
			sid = section[".name"]
			return false
		end
		if final_path ~= "" and section.clash_path == final_path then
			sid = section[".name"]
			return false
		end
	end)

	return sid
end

local function save_uploaded_clash_node(upload_name, final_path)
	local sid = find_uploaded_clash_section(upload_name, final_path)
	local old_path
	local alias

	if not sid then
		sid = uci:add("shadowsocksr", "servers")
	end
	if not sid then
		return nil
	end

	old_path = uci:get("shadowsocksr", sid, "clash_path")
	alias = uci:get("shadowsocksr", sid, "alias")
	if not alias or alias == "" then
		alias = upload_alias(upload_name)
	end

	uci:set("shadowsocksr", sid, "type", "clash")
	uci:set("shadowsocksr", sid, "alias", alias)
	uci:set("shadowsocksr", sid, "server", "127.0.0.1")
	uci:set("shadowsocksr", sid, "server_port", "0")
	uci:delete("shadowsocksr", sid, "clash_url")
	uci:set("shadowsocksr", sid, "clash_path", final_path)
	uci:set("shadowsocksr", sid, "clash_user_agent", uci:get("shadowsocksr", sid, "clash_user_agent") or "clash")
	if not uci:get("shadowsocksr", sid, "switch_enable") then
		uci:set("shadowsocksr", sid, "switch_enable", uci:get_first("shadowsocksr", "server_subscribe", "switch", "1") or "1")
	end
	uci:set("shadowsocksr", sid, "yaml_upload", "1")
	uci:set("shadowsocksr", sid, "yaml_upload_name", upload_name)
	uci:save("shadowsocksr")
	uci:commit("shadowsocksr")

	cleanup_old_clash_path(old_path, final_path, sid)
	luci.sys.call(string.format("/etc/init.d/shadowsocksr clash_cache %s >/dev/null 2>&1 &", luci.util.shellquote(sid)))
	return sid, alias
end

local has_mihomo = is_finded("mihomo")
local upload_fd
local upload_tmp_path
local upload_filename
local upload_message
local upload_errmessage

if has_mihomo then
	luci.http.setfilehandler(function(meta, chunk, eof)
		if not meta or meta.name ~= "clash_yaml_file" then
			return
		end

		if not upload_fd then
			if not meta.file or meta.file == "" then
				return
			end
			upload_filename = tostring(meta.file):gsub("[\r\n]", "")
			upload_tmp_path = string.format("/tmp/ssrplus-clash-upload-%d-%d.yaml", nixio.getpid(), os.time())
			upload_fd = nixio.open(upload_tmp_path, "w")
			if not upload_fd then
				upload_errmessage = translate("Failed to create temporary YAML upload file.")
				upload_tmp_path = nil
				upload_filename = nil
				return
			end
		end

		if chunk and upload_fd then
			upload_fd:write(chunk)
		end

		if eof and upload_fd then
			upload_fd:close()
			upload_fd = nil
		end
	end)

	if luci.http.formvalue("upload_clash_yaml") then
		if not upload_tmp_path or not upload_filename or not nixio.fs.access(upload_tmp_path) then
			upload_errmessage = upload_errmessage or translate("No custom YAML file was selected.")
		else
			local hash
			local final_path
			local tmp_output = string.format("%s/.upload-%d-%d.yaml", CLASH_YAML_DIR, nixio.getpid(), os.time())
			local sid
			local alias

			nixio.fs.mkdirr(CLASH_YAML_DIR)
			nixio.fs.remove(tmp_output)
			if preprocess_clash_yaml(upload_tmp_path, tmp_output) then
				hash = hash_file(tmp_output)
				if hash == "" then
					nixio.fs.remove(tmp_output)
					upload_errmessage = translate("Uploaded YAML validation or preprocessing failed.")
				else
					final_path = string.format("%s/%s.yaml", CLASH_YAML_DIR, hash)
					luci.sys.call(string.format("mv -f %s %s", luci.util.shellquote(tmp_output), luci.util.shellquote(final_path)))
					sid, alias = save_uploaded_clash_node(upload_filename, final_path)
					if sid then
						upload_message = string.format(translate("Custom YAML imported successfully: %s"), alias or sid)
					else
						upload_errmessage = translate("Uploaded YAML validation or preprocessing failed.")
					end
				end
			else
				nixio.fs.remove(tmp_output)
				upload_errmessage = translate("Uploaded YAML validation or preprocessing failed.")
			end
		end

		if upload_tmp_path then
			nixio.fs.remove(upload_tmp_path)
		end
	end
end

local function preserve_when_hidden(opt, controller, enabled_value)
	local original_parse = opt.parse

	opt.parse = function(self, section, novld)
		local current = self.map:get(section, controller)
		if current == nil then
			current = self.map:formvalue("cbid." .. self.map.config .. "." .. section .. "." .. controller)
		end
		if tostring(current or "") ~= tostring(enabled_value) then
			return
		end
		return original_parse(self, section, novld)
	end
end

local function migrate_legacy_subscribe_urls()
	local subscribe_sid = uci:get_first("shadowsocksr", "server_subscribe")
	if not subscribe_sid then
		return
	end

	local legacy_urls = uci:get_list("shadowsocksr", subscribe_sid, "subscribe_url") or {}
	if #legacy_urls == 0 then
		return
	end

	local has_items = false
	uci:foreach("shadowsocksr", "server_subscribe_item", function()
		has_items = true
		return false
	end)
	if has_items then
		return
	end

	for index, url in ipairs(legacy_urls) do
		local trimmed = trim(url)
		if trimmed ~= "" then
			local sid_output = luci.sys.exec("uci add shadowsocksr server_subscribe_item")
			local sid = sid_output:match("%S+")
			if sid and sid ~= "" then
				local escaped_sid = luci.util.shellquote(sid)
				local alias = string.format("Subscribe %d", index)
				local escaped_alias = luci.util.shellquote(alias)
				local escaped_url = luci.util.shellquote(trimmed)
				luci.sys.call("uci set shadowsocksr." .. escaped_sid .. ".enabled=1")
				luci.sys.call("uci set shadowsocksr." .. escaped_sid .. ".alias=" .. escaped_alias)
				luci.sys.call("uci set shadowsocksr." .. escaped_sid .. ".url=" .. escaped_url)
			end
		end
	end

	luci.sys.call("uci delete shadowsocksr." .. subscribe_sid .. ".subscribe_url")
	luci.sys.call("uci commit shadowsocksr")
end

local function clash_host_port(clash_url)
	if not clash_url or clash_url == "" then
		return nil, nil
	end
	local ok, parsed = pcall(URL.parse, clash_url)
	if not ok or not parsed then
		return nil, nil
	end
	local host = parsed.host
	local port = parsed.port
	if not port or port == "" then
		port = (parsed.scheme == "http") and "80" or "443"
	end
	return host, port
end

migrate_legacy_subscribe_urls()

uci:foreach("shadowsocksr", "servers", function(s)
	server_count = server_count + 1
	server_sections[#server_sections + 1] = s[".name"]
	server_cache[s[".name"]] = {
		type = s.type,
		v2ray_protocol = s.v2ray_protocol,
		alias = s.alias,
		server_port = s.server_port,
		server = s.server,
		transport = s.transport,
		ws_path = s.ws_path,
		ws_host = s.ws_host,
		tls_host = s.tls_host,
		tls = s.tls,
		reality = s.reality,
		clash_url = s.clash_url
	}
end)

local function get_server(section)
	return server_cache[section] or {}
end

do
	local raw = nixio.fs.readfile("/tmp/ssrplus_server_detect.json")
	if raw and raw ~= "" then
		local parsed = json.parse(raw)
		if type(parsed) == "table" then
			detect_cache = parsed
		end
	end
end

m = Map("shadowsocksr", translate("Servers subscription and manage"))
if upload_errmessage then
	m.errmessage = upload_errmessage
elseif upload_message then
	m.message = upload_message
end

local style_section = m:section(SimpleSection)
style_section.template = "shadowsocksr/servers_subscribe_url_style"

-- Server Subscribe
s = m:section(TypedSection, "server_subscribe")
s.anonymous = true

o = s:option(Flag, "auto_update", translate("Auto Update"))
o.rmempty = false
o.description = translate("Auto Update Server subscription, GFW list and CHN route")

o = s:option(ListValue, "config_auto_update_mode", translate("Update Mode"))
o:value("0", translate("Appointment Mode"))
o:value("1", translate("Loop Mode"))
o.default = "0"
o.rmempty = true
o:depends("auto_update", "1")

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
o:depends({auto_update = "1", config_auto_update_mode = "0"})

o = s:option(ListValue, "auto_update_day_time", translate("Regular update (Hour)"))
for t = 0, 23 do
	o:value(t, t .. ":00")
end
o.default = 2
o.rmempty = true
o:depends({auto_update = "1", config_auto_update_mode = "0"})

o = s:option(ListValue, "auto_update_min_time", translate("Regular update (Min)"))
for i = 0, 59 do
	o:value(i, i .. ":00")
end
o.default = 30
o.rmempty = true
o:depends({auto_update = "1", config_auto_update_mode = "0"})

o = s:option(Value, "config_update_interval", translate("Update Interval(min)"))
o.default = "60"
o.datatype = "uinteger"
o.rmempty = true
o:depends({auto_update = "1", config_auto_update_mode = "1"})

o = s:option(Flag, "_subscribe_advanced_toggle", translate("Subscribe Advanced Settings"))
o.rmempty = false
o.default = "0"
o.write = function() end
o.remove = function() end

o = s:option(Value, "filter_words", translate("Subscribe Filter Words"))
o.rmempty = true
o.default = "过期/重置/套餐/剩余/网址/QQ群/官网/防失联/回国"
o.description = translate("Filter Words splited by /")
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

o = s:option(Value, "save_words", translate("Subscribe Save Words"))
o.rmempty = true
o.description = translate("Save Words splited by /")
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

o = s:option(Flag, "allow_insecure", translate("Allow subscribe Insecure nodes By default"))
o.rmempty = false
o.description = translate("Subscribe nodes allows insecure connection as TLS client (insecure)")
o.default = "0"
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

o = s:option(Flag, "switch", translate("Subscribe Default Auto-Switch"))
o.rmempty = false
o.description = translate("Subscribe new add server default Auto-Switch on")
o.default = "1"
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

o = s:option(Flag, "proxy", translate("Through proxy update"))
o.rmempty = false
o.description = translate("Through proxy update list, Not Recommended ")
o.default = "1"
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

o = s:option(Button, "_save_subscribe_settings", translate("Save Subscribe Settings"))
o.inputstyle = "save"
o.description = translate("Save current subscribe settings")
o.write = function() end

o = s:option(Button, "subscribe", translate("Update All Subscribe Servers"))
o.rawhtml = true
o.template = "shadowsocksr/subscribe"
o.write = function(self, section)
	self.map.ssr_subscribe_requested = true
end

o = s:option(Button, "delete", translate("Delete All Subscribe Servers"))
o.inputstyle = "reset"
o.description = string.format(translate("Server Count") .. ": %d", server_count)
o.write = function()
	uci:delete_all("shadowsocksr", "servers", function(s)
		if s.hashkey or s.isSubscribe then
			return true
		else
			return false
		end
	end)
	uci:save("shadowsocksr")
	uci:commit("shadowsocksr")
	for file in nixio.fs.glob("/tmp/sub_md5_*") do
		nixio.fs.remove(file)
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "delete"))
	return
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
o:depends("_subscribe_advanced_toggle", "1")
preserve_when_hidden(o, "_subscribe_advanced_toggle", "1")

if has_mihomo then
	o = s:option(DummyValue, "_upload_clash_yaml", translate("Upload Custom YAML File"))
	o.template = "shadowsocksr/clash_yaml_upload"
	o.description = translate("Upload a custom Clash/Mihomo YAML file. The file will be preprocessed and saved as a local Clash node.")

	o = s:option(Flag, "enable_mihomo", string.format("<b><span style='color:red;'>%s</span></b>", translate("Enable Mihomo core")))
	o.default = "0"
	o.rmempty = true
	o.description = translate("Disabled means use Xray or ShadowSocks-Rust core.")

	o = s:option(Flag, "sub_convert", translate("Subscribe Convert Online"))
	o.description = translate("Convert subscriptions to Clash/Mihomo YAML with a subscription template URL.")
	o.default = "0"
	o.rmempty = false
	o:depends("enable_mihomo", "1")

	o = s:option(Value, "convert_address", translate("Convert Address"))
	o.default = "https://api.asailor.org/sub"
	o.placeholder = "https://api.asailor.org/sub"
	o:value("https://api.asailor.org/sub", "api.asailor.org")
	o:value("https://api.wcc.best/sub", "api.wcc.best")
	o.rmempty = true
	o:depends("sub_convert", "1")

	o = s:option(Value, "template_url", translate("Subscribe Template URL"))
	o.default = "https://raw.githubusercontent.com/Fzlwhyc/OpenClash-Templates/main//fzlwhyc-openclash.ini"
	o.placeholder = "https://raw.githubusercontent.com/Fzlwhyc/OpenClash-Templates/main//fzlwhyc-openclash.ini"
	o:value("https://raw.githubusercontent.com/Fzlwhyc/OpenClash-Templates/main//fzlwhyc-openclash.ini", "Fzlwhyc")
	o:value("https://gist.githubusercontent.com/vernesong/4c27ed54ab2a5fedd9c4011389ac11ed/raw/lhie1_clash.ini", "lhie1")
	o.rmempty = true
	o:depends("sub_convert", "1")
end

s:append(cbi.Template("shadowsocksr/subscribe_schedule_compact"))

s = m:section(TypedSection, "server_subscribe_item", translate("Subscribe URL"))
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "shadowsocksr/subscribe_actions_footer"
--s.template = "cbi/tblsection"
--s.template_addremove = "shadowsocksr/subscribe_actions_footer"
s.description = translate("Manage multiple subscribe URLs, including Clash subscriptions. Only enabled entries are included when updating all subscriptions.")

o = s:option(Flag, "enabled", translate("Enable"))
o.rmempty = false
o.default = "1"
o.width = "1%"
function o.cfgvalue(...)
	return Flag.cfgvalue(...) or "1"
end

o = s:option(Value, "alias", translate("Alias"))
o.rmempty = true
o.width = "7.5rem"
function o.cfgvalue(self, section)
	return Value.cfgvalue(self, section) or string.format("Subscribe %s", section:sub(-4))
end

o = s:option(Value, "url", translate("Subscribe URL"))
o.rmempty = false

-- [[ Servers Manage ]]--
s = m:section(TypedSection, "servers")
s.anonymous = true
s.addremove = true
s.description = translate("Node order can be dragged with the mouse and takes effect immediately. The automatic switch order of server nodes is consistent with the node order in the table.")
s.template = "shadowsocksr/server_table"
set_apply_on_parse(m)
s:append(cbi.Template("shadowsocksr/optimize_cbi_ui"))
s.extedit = luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers", "%s")

local server_page_size = parse_nonnegative_int(luci.http.formvalue("server_page_size"))
if not server_page_size or not in_list(SERVER_PAGE_SIZE_OPTIONS, server_page_size) then
	server_page_size = DEFAULT_SERVER_PAGE_SIZE
end

local server_page_count = 1
if server_page_size > 0 and server_count > 0 then
	server_page_count = math.ceil(server_count / server_page_size)
end

local server_page = parse_nonnegative_int(luci.http.formvalue("server_page")) or 1
if server_page < 1 then
	server_page = 1
end
if server_page > server_page_count then
	server_page = server_page_count
end

local visible_server_sections = server_sections
local server_first_index = server_count > 0 and 1 or 0
local server_last_index = server_count

if server_page_size > 0 then
	local first = ((server_page - 1) * server_page_size) + 1
	local last = math.min(first + server_page_size - 1, server_count)
	visible_server_sections = {}
	server_first_index = server_count > 0 and first or 0
	server_last_index = server_count > 0 and last or 0

	for index = first, last do
		visible_server_sections[#visible_server_sections + 1] = server_sections[index]
	end
end

s.sortable = true

function s.cfgsections(self)
	return visible_server_sections
end

s.server_page = server_page
s.server_page_size = server_page_size
s.server_page_count = server_page_count
s.server_page_sizes = SERVER_PAGE_SIZE_OPTIONS
s.server_total = server_count
s.server_first_index = server_first_index
s.server_last_index = server_last_index
s.server_base_url = luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers")

function s.create(self, ...)
	local used_sid = {}
	local next_sid = 1

	self.map.uci:foreach(self.config, self.sectiontype, function(s)
		local num = s[".name"]:match("^cfg(%x%x)")
		if num then
			local n = tonumber(num, 16)
			if n then
				used_sid[n] = true
			end
		end
	end)

	local function get_next_sid()
		while used_sid[next_sid] do
			next_sid = next_sid + 1
		end
		used_sid[next_sid] = true
		return next_sid
	end

	local sid = TypedSection.create(self, ...)	
	if sid then
		local suffix = sid:sub(-4)
		self.map.uci:delete(self.config, sid)
		local id = get_next_sid()
		local newsid = string.format("cfg%02x%s", id, suffix)
		local success = self.map.uci:section(self.config, self.sectiontype, newsid)
		if success then
			--self.map.uci:save(self.config)
			luci.http.redirect(self.extedit % newsid)
			return
		end
	end
end

o = s:option(DummyValue, "type", translate("Type"))
function o.cfgvalue(self, section)
	local cfg = get_server(section)
	return cfg.v2ray_protocol or cfg.type or translate("None")
end

o = s:option(DummyValue, "alias", translate("Alias"))
function o.cfgvalue(self, section)
	return get_server(section).alias or translate("None")
end

o = s:option(DummyValue, "server_port", translate("Socket Connected"))
o.template = "shadowsocksr/socket"
o.width = "10%"
function o.cfgvalue(self, section)
	self.detect_cache = detect_cache[section]
	local cfg = get_server(section)
	local stype = cfg.type
	if stype == "clash" then
		return "N/A"
	end
	return cfg.server_port
end
o.render = function(self, section, scope)
	local cfg = get_server(section)
	local stype = cfg.type
	self.type = stype or ""
	self.proto = cfg.v2ray_protocol or ""
	self.reality = cfg.reality or ""
	if stype == "clash" then
		self.transport = ""
		self.ws_path = ""
		self.ws_host = ""
		self.tls_host = ""
		self.tls = ""
		self.reality = ""
	else
		self.transport = cfg.transport or ""
		self.ws_host = cfg.ws_host or ""
		self.tls_host = cfg.tls_host or ""
		if self.transport == 'ws' then
			self.ws_path = cfg.ws_path or ""
			self.tls = cfg.tls or ""
		else
			self.ws_path = ""
			self.tls = ""
		end
	end
	DummyValue.render(self, section, scope)
end

o = s:option(DummyValue, "server", translate("Ping Latency"))
o.template = "shadowsocksr/ping"
o.width = "10%"
function o.cfgvalue(self, section)
	self.detect_cache = detect_cache[section]
	local cfg = get_server(section)
	self.type = cfg.type or ""
	if cfg.type == "clash" then
		return "N/A"
	end
	return cfg.server or "N/A"
end

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
	local safe_section = luci.util.shellquote(section)
	local cmd = string.format("uci set shadowsocksr.@global[0].global_server=%s && uci commit shadowsocksr", safe_section)
	luci.sys.call(cmd)
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "restart"))
end

o = s:option(Flag, "switch_enable", translate("Auto Switch"))
o.rmempty = false
function o.cfgvalue(...)
	return Value.cfgvalue(...) or 1
end

m:append(cbi.Template("shadowsocksr/server_list"))

m.commit_handler = function(self)
	if not self.ssr_subscribe_requested then
		return
	end

	for _, config in ipairs(self.parsechain or {}) do
		self.uci:commit(config)
	end
	self.ssr_subscribe_autostart = true
end

return m
