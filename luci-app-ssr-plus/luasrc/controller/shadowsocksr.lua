-- Copyright (C) 2017 yushi studio <ywb94@qq.com>
-- Licensed to the public under the GNU General Public License v3.
module("luci.controller.shadowsocksr", package.seeall)
require "nixio"
require "nixio.fs"
require "luci.util"
require "luci.template"
require "luci.sys"
local i18n = require "luci.i18n"
local datatypes = require "luci.cbi.datatypes"
local json = require "luci.jsonc"
local uci = require "luci.model.uci".cursor()
local translate = i18n.translate

local CLASH_API_PORT = "16756"
local COMPONENT_HELPER = "/usr/share/shadowsocksr/update_components.sh"
local SERVER_DETECT_CACHE = "/tmp/ssrplus_server_detect.json"
local SERVER_DETECT_LOCK = "/tmp/ssrplus_server_detect.lock"
local CLASH_RULES_DIR = "/etc/ssrplus/clash"
local SUPPORTED_COMPONENTS = {
	xray = true,
	mihomo = true,
	naiveproxy = true
}
local SUPPORTED_GEO_COMPONENTS = {
	country_mmdb = true,
	geosite = true,
	v2ray_geo = true
}

local function trim(value)
	return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
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

local function sanitize_mac(value)
	value = trim(value):upper():gsub("-", ":")
	if value:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
		return value
	end
	return ""
end

local function normalize_client_ip(value)
	value = trim(value)
	if value == "" then
		return ""
	end
	if datatypes.cidr4(value) or datatypes.ip4addr(value) then
		return value
	end
	return ""
end

local function get_clash_client_rule_csv_path(sid)
	sid = trim(sid)
	if sid == "" then
		return nil
	end
	return string.format("%s/%s.csv", CLASH_RULES_DIR, sid)
end

local function csv_escape(value)
	value = tostring(value or "")
	if value:find('[",\n\r]') then
		return '"' .. value:gsub('"', '""') .. '"'
	end
	return value
end

local function parse_csv_line(line)
	local cols = {}
	local cur = ""
	local in_quote = false
	local i = 1

	while i <= #line do
		local ch = line:sub(i, i)
		if ch == '"' then
			if in_quote and line:sub(i + 1, i + 1) == '"' then
				cur = cur .. '"'
				i = i + 1
			else
				in_quote = not in_quote
			end
		elseif ch == "," and not in_quote then
			cols[#cols + 1] = cur
			cur = ""
		else
			cur = cur .. ch
		end
		i = i + 1
	end

	cols[#cols + 1] = cur
	return cols
end

local function read_clash_client_rules_csv(sid)
	local rules = {}
	local csv_path = get_clash_client_rule_csv_path(sid)
	if not csv_path or not nixio.fs.access(csv_path) then
		return rules
	end

	local raw = nixio.fs.readfile(csv_path)
	if not raw or raw == "" then
		return rules
	end

	local first = true
	for line in tostring(raw):gsub("\r", ""):gmatch("[^\n]+") do
		local text = trim(line)
		if text ~= "" then
			if first and text:lower() == "enabled,client,policy,remarks,client_mac" then
				first = false
			else
				local cols = parse_csv_line(line)
				if #cols >= 4 then
					rules[#rules + 1] = {
						id = tostring(#rules + 1),
						enabled = cols[1] == "1" or tostring(cols[1] or ""):lower() == "true",
						ip_addr = trim(cols[2] or ""),
						policy_group = trim(cols[3] or ""),
						remarks = trim(cols[4] or ""),
						client_mac = sanitize_mac(cols[5] or "")
					}
				end
			end
		end
	end

	return rules
end

local function write_clash_client_rules_csv(sid, rows)
	local csv_path = get_clash_client_rule_csv_path(sid)
	if not csv_path then
		return false
	end

	nixio.fs.mkdirr(CLASH_RULES_DIR)
	local lines = { "enabled,client,policy,remarks,client_mac" }
	for _, row in ipairs(rows or {}) do
		lines[#lines + 1] = table.concat({
			row.enabled == "1" and "1" or "0",
			csv_escape(row.ip_addr or ""),
			csv_escape(row.policy_group or ""),
			csv_escape(row.remarks or ""),
			csv_escape(row.client_mac or "")
		}, ",")
	end

	return nixio.fs.writefile(csv_path, table.concat(lines, "\n") .. "\n")
end

local function collect_lan_clients()
	local clients = {}
	local seen = {}

	luci.sys.net.host_hints(function(mac, ipv4, _, name)
		local ip = trim(ipv4)
		local norm_mac = sanitize_mac(mac)
		if ip ~= "" and not seen[ip] then
			seen[ip] = true
			clients[#clients + 1] = {
				ip = ip,
				mac = norm_mac,
				name = trim(name) ~= "" and trim(name) or ip
			}
		end
	end)

	table.sort(clients, function(a, b)
		return tostring(a.name or a.ip) < tostring(b.name or b.ip)
	end)

	return clients
end

local function read_clash_client_rules(sid)
	return read_clash_client_rules_csv(sid)
end

local function normalize_ping_ms(value, scale)
	local num = tonumber(value)
	if not num or num <= 0 then
		return nil
	end
	local scaled = scale and (num * scale) or num
	if scaled > 0 and scaled < 1 then
		return 1
	end
	return math.floor(scaled + 0.5)
end

local function detect_tls_handshake_ms(domain, port, path, resolve_host, server_ip, is_websocket)
	if not domain or domain == "" or not port or port <= 0 then
		return nil
	end

	local final_host = (resolve_host and resolve_host ~= "") and resolve_host or domain
	local resolve_arg = ""
	if server_ip and server_ip ~= "" and final_host ~= server_ip then
		resolve_arg = string.format("--resolve '%s:%d:%s' ", final_host, port, server_ip)
	end

	local ws_headers = ""
	if is_websocket then
		ws_headers = string.format(
			"-H %s -H %s -H %s -H %s ",
			luci.util.shellquote("Connection: Upgrade"),
			luci.util.shellquote("Upgrade: websocket"),
			luci.util.shellquote("Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ=="),
			luci.util.shellquote("Sec-WebSocket-Version: 13")
		)
	end

	local host_header = (final_host and final_host ~= "") and ("-H " .. luci.util.shellquote("Host: " .. final_host) .. " ") or ""
	local url = string.format("https://%s:%d%s", final_host, port, path or "")
	local cmd = string.format(
		"curl --http1.1 -m 3 -ksS -o /dev/null %s%s%s -w 'time_connect=%%{time_connect}\\ntime_appconnect=%%{time_appconnect}\\nhttp_code=%%{http_code}' '%s' 2>/dev/null",
		resolve_arg, host_header, ws_headers, url
	)
	local result = luci.sys.exec(cmd) or ""
	local appconnect = tonumber(result:match("time_appconnect=([0-9.]+)"))
	if appconnect and appconnect > 0 then
		return normalize_ping_ms(appconnect, 1000)
	end
	local connect = tonumber(result:match("time_connect=([0-9.]+)"))
	if connect and connect > 0 then
		return normalize_ping_ms(connect, 1000)
	end
	return nil
end

local function urlencode(str)
	if not str then return "" end
	return tostring(str):gsub("[^%w%-_%.~]", function(c)
		return string.format("%%%02X", string.byte(c))
	end)
end

local function is_ipv6_address(addr)
	addr = tostring(addr or "")
	return addr ~= "" and addr:find(":", 1, true) ~= nil
end

local function is_local_target(addr)
	addr = tostring(addr or ""):lower()
	if addr == "" then
		return false
	end

	if addr == "localhost" or addr == "::1" or addr:match("%.local$") then
		return true
	end

	if is_ipv6_address(addr) then
		return addr:match("^fe[89ab]") ~= nil or addr:match("^fc") ~= nil or addr:match("^fd") ~= nil
	end

	local o1, o2 = addr:match("^(%d+)%.(%d+)%.")
	o1 = tonumber(o1)
	o2 = tonumber(o2)
	if not o1 or not o2 then
		return false
	end

	return o1 == 10
		or o1 == 127
		or (o1 == 169 and o2 == 254)
		or (o1 == 172 and o2 >= 16 and o2 <= 31)
		or (o1 == 192 and o2 == 168)
end

local function detect_tcp_connect_ms(domain, port)
	if not domain or domain == "" or not port or port <= 0 then
		return nil
	end

	local ip_version_arg = is_ipv6_address(domain) and "-6 " or ""
	local cmd = string.format(
		"nping %s--tcp-connect -q -c 1 -p %d %s 2>/dev/null",
		ip_version_arg,
		port,
		luci.util.shellquote(domain)
	)
	local result = luci.sys.exec(cmd) or ""
	local success = tonumber(result:match("Successful connections:%s*([0-9]+)"))
	if success and success > 0 then
		local avg_rtt = tonumber(result:match("Avg rtt:%s*([0-9.]+)ms"))
		if avg_rtt and avg_rtt > 0 and avg_rtt < 1 and not is_local_target(domain) then
			return nil
		end
		return normalize_ping_ms(avg_rtt)
	end

	return nil
end

local function get_clash_secret(sid)
	return sid .. "_ssrplus_clash"
end

local function get_clash_cache_file(sid)
	return "/etc/ssrplus/clash/" .. sid .. ".yaml"
end

local function get_clash_state_file(sid)
	return "/etc/ssrplus/clash/" .. sid .. ".cache.db"
end

local function clash_process_running()
	return luci.sys.call("(busybox ps -w 2>/dev/null || busybox ps) | grep ssr-retcp | grep -v grep >/dev/null") == 0
end

local function global_client_running()
	local process_list = luci.sys.exec("busybox ps -w 2>/dev/null || busybox ps")
	local global_server = uci:get_first("shadowsocksr", "global", "global_server", "nil")
	local global_type = global_server ~= "nil" and (uci:get("shadowsocksr", global_server, "type") or "") or ""

	if process_list:find("tcp.only.ssr.retcp")
		or process_list:find("tcp.udp.ssr.retcp")
		or process_list:find("local.ssr.retcp")
		or process_list:find("local.udp.ssr.retcp") then
		return true
	end

	if (global_type == "clash" or global_type == "v2ray" or global_type == "tuic" or global_type == "ss" or global_type == "ss-rust")
		and process_list:find("ssr%-retcp") then
		return true
	end

	if (global_type == "clash" or global_type == "v2ray" or global_type == "tuic" or global_type == "ss" or global_type == "ss-rust")
		and process_list:find("mihomo")
		and (process_list:find("/clash%-") or process_list:find("/v2ray%-") or process_list:find("/tuic%-") or process_list:find("/ss%-")) then
		return true
	end

	if global_type == "socks5"
		and process_list:find("ipt2socks")
		and (process_list:find("%-T") or process_list:find("%-%-tcp%-only")) then
		return true
	end

	return false
end

local function get_active_node_runtime(sid)
	if not sid or sid == "" or sid == "nil" or uci:get("shadowsocksr", sid) ~= "servers" then
		return nil, nil
	end

	local stype = (uci:get("shadowsocksr", sid, "type") or ""):lower()
	local proto = (uci:get("shadowsocksr", sid, "v2ray_protocol") or ""):lower()
	local backend
	local protocol

	local is_mihomo_running = luci.sys.call("pgrep -x ssr-retcp >/dev/null 2>&1") == 0

	if stype == "ss" then
		backend = translate("Mihomo")
		protocol = translate("ShadowSocks")
	elseif stype == "clash" then
		backend = translate("Mihomo")
		protocol = translate("Clash")
	elseif stype == "tuic" then
		backend = translate("Mihomo")
		protocol = translate("TUIC")
	elseif stype == "ssr" then
		backend = translate("ShadowsocksR")
	elseif stype == "ss-rust" then
		if is_mihomo_running then
			backend = translate("Mihomo")
			protocol = translate("ShadowSocks-Rust")
		else
			backend = translate("ShadowSocks-Rust")
		end
	elseif stype == "v2ray" then
		local proto_map = {
			vmess = "VMess",
			vless = "VLESS",
			trojan = "Trojan",
			socks = "SOCKS5",
			hysteria2 = "Hysteria2",
			shadowsocks = "Shadowsocks",
			http = "HTTP"
		}
		if is_mihomo_running then
			backend = translate("Mihomo")
		else
			backend = translate("Xray")
		end
		if proto_map[proto] then
			protocol = translate(proto_map[proto])
		end
	elseif stype == "trojan" then
		backend = translate("Trojan")
	elseif stype == "naiveproxy" then
		backend = translate("NaiveProxy")
	elseif stype == "socks5" then
		backend = translate("SOCKS5")
	elseif stype == "shadowtls" then
		backend = translate("ShadowTLS")
	elseif stype == "hysteria2" then
		backend = translate("Hysteria2")
	end

	if not backend or backend == "" then
		backend = trim(stype)
	end

	return backend, protocol
end

local function get_running_status_text()
	local sid = uci:get_first("shadowsocksr", "global", "global_server", "nil")
	local backend, protocol = get_active_node_runtime(sid)

	if backend and backend ~= "" and protocol and protocol ~= "" and backend ~= protocol then
		return string.format(translate("RUNNING in %s (%s) Mode"), backend, protocol)
	end

	if backend and backend ~= "" then
		return string.format(translate("RUNNING in %s Mode"), backend)
	end

	return translate("RUNNING")
end

local function is_active_clash_node(sid)
	if not sid then return false end
	if uci:get("shadowsocksr", sid) ~= "servers" then return false end
	if uci:get("shadowsocksr", sid, "type") ~= "clash" then return false end
	if uci:get_first("shadowsocksr", "global", "global_server") ~= sid then return false end
	return clash_process_running()
end

local function resolve_active_clash_sid(sid)
	if is_active_clash_node(sid) then
		return sid
	end

	local current_sid = uci:get_first("shadowsocksr", "global", "global_server")
	if is_active_clash_node(current_sid) then
		return current_sid
	end

	return nil
end

local function clash_api_request(sid, method, path, body)
	sid = resolve_active_clash_sid(sid)
	if not sid then
		return nil
	end
	local secret = get_clash_secret(sid)
	local cmd = string.format(
		"curl -sL -m 5 --retry 1 -w '\n__CURL_STATUS__:%%{http_code}' -H %s -H %s -X %s http://127.0.0.1:%s%s %s",
		luci.util.shellquote("Content-Type: application/json"),
		luci.util.shellquote("Authorization: Bearer " .. secret),
		method,
		CLASH_API_PORT,
		path,
		body and ("-d " .. luci.util.shellquote(body)) or ""
	)
	local output = luci.sys.exec(cmd)
	if not output or output == "" then
		return nil
	end
	local body_output = output:gsub("\n__CURL_STATUS__:%d%d%d%s*$", "")
	local code = output:match("__CURL_STATUS__:(%d%d%d)")
	return {
		code = tonumber(code),
		body = body_output
	}
end

local function use_fw4_backend()
	return luci.sys.call("command -v fw4 >/dev/null") == 0
end

local function parse_clash_groups(raw)
	local info = json.parse(raw or "")
	local proxies = info and info.proxies or nil
	local groups = {}
	if type(proxies) ~= "table" then
		return groups
	end
	for name, value in pairs(proxies) do
		if type(value) == "table" and type(value.all) == "table" and #value.all > 0 then
			groups[#groups + 1] = {
				name = name,
				type = value.type or "",
				now = value.now or "",
				all = value.all
			}
		end
	end
	table.sort(groups, function(a, b) return tostring(a.name) < tostring(b.name) end)
	return groups
end

local function parse_kv_output(raw)
	local data = {}
	for line in tostring(raw or ""):gmatch("[^\r\n]+") do
		local key, value = line:match("^([%w_]+)=(.*)$")
		if key then
			data[key] = value
		end
	end
	return data
end

local function with_detect_cache_lock(fn)
	for _ = 1, 40 do
		if nixio.fs.mkdir(SERVER_DETECT_LOCK) then
			local ok, ret = pcall(fn)
			nixio.fs.rmdir(SERVER_DETECT_LOCK)
			if ok then
				return ret
			end
			return nil
		end
		nixio.nanosleep(0, 50000000)
	end
	return nil
end

local function load_detect_cache()
	local raw = nixio.fs.readfile(SERVER_DETECT_CACHE)
	if not raw or raw == "" then
		return {}
	end
	local parsed = json.parse(raw)
	return type(parsed) == "table" and parsed or {}
end

local function save_detect_cache_entry(sid, data)
	if not sid or sid == "" then
		return
	end
	with_detect_cache_lock(function()
		local cache = load_detect_cache()
		cache[sid] = data
		nixio.fs.writefile(SERVER_DETECT_CACHE, json.stringify(cache))
	end)
end

local function read_component_state(component, action)
	if not SUPPORTED_COMPONENTS[component] then
		return nil, 400, "unsupported_component"
	end

	local mirror = luci.http.formvalue("mirror") or ""
	local cmd = string.format(
		"COMPONENT_MIRROR=%s /bin/sh %s %s 2>/dev/null",
		luci.util.shellquote(mirror),
		luci.util.shellquote(COMPONENT_HELPER),
		luci.util.shellquote(component .. "_" .. action)
	)
	return parse_kv_output(luci.sys.exec(cmd))
end

local function read_geo_state(component, action)
	if not SUPPORTED_GEO_COMPONENTS[component] then
		return nil, 400, "unsupported_component"
	end

	local mirror = luci.http.formvalue("mirror") or ""
	local cmd = string.format(
		"COMPONENT_MIRROR=%s /bin/sh %s %s 2>/dev/null",
		luci.util.shellquote(mirror),
		luci.util.shellquote(COMPONENT_HELPER),
		luci.util.shellquote(component .. "_" .. action)
	)
	return parse_kv_output(luci.sys.exec(cmd))
end

local function write_component_json(data)
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		component = data.component or "xray",
		installed = data.installed == "1",
		current_version = data.current_version or "",
		latest_version = data.latest_version or "",
		previous_version = data.previous_version or "",
		arch = data.arch or "",
		asset = data.asset or "",
		can_upgrade = data.can_upgrade == "1",
		success = data.success == "1",
		error = data.error or "",
		message = data.message or ""
	})
end

local function write_geo_json(data)
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		component = data.component or "country_mmdb",
		installed = data.installed == "1",
		current_version = data.current_version or "",
		current_version_extra = data.current_version_extra or "",
		latest_version = data.latest_version or "",
		can_upgrade = data.can_upgrade == "1",
		success = data.success == "1",
		error = data.error or "",
		message = data.message or ""
	})
end

local function shell_quote(value)
	return "'" .. tostring(value or ""):gsub("'", "'\\''") .. "'"
end

function index()
	if not nixio.fs.access("/etc/config/shadowsocksr") then
		call("act_reset")
	end
	local page
	page = entry({"admin", "services", "shadowsocksr"}, alias("admin", "services", "shadowsocksr", "client"), _("ShadowSocksR Plus+"), 10)
	page.dependent = true
	page.acl_depends = { "luci-app-ssr-plus" }
	entry({"admin", "services", "shadowsocksr", "client"}, cbi("shadowsocksr/client"), _("SSR Client"), 10).leaf = true
	entry({"admin", "services", "shadowsocksr", "servers"}, arcombine(cbi("shadowsocksr/servers"), cbi("shadowsocksr/client-config")), _("Servers Nodes"), 20).leaf = true
	entry({"admin", "services", "shadowsocksr", "control"}, cbi("shadowsocksr/control"), _("Access Control"), 30).leaf = true
	entry({"admin", "services", "shadowsocksr", "advanced"}, cbi("shadowsocksr/advanced"), _("Advanced Settings"), 50).leaf = true
	entry({"admin", "services", "shadowsocksr", "server"}, arcombine(cbi("shadowsocksr/server"), cbi("shadowsocksr/server-config")), _("SSR Server"), 60).leaf = true
	entry({"admin", "services", "shadowsocksr", "component"}, cbi("shadowsocksr/component"), _("Component Update"), 65).leaf = true
	entry({"admin", "services", "shadowsocksr", "status"}, form("shadowsocksr/status"), _("Status"), 70).leaf = true
	entry({"admin", "services", "shadowsocksr", "check"}, call("check_status"))
	entry({"admin", "services", "shadowsocksr", "refresh"}, call("refresh_data"))
	entry({"admin", "services", "shadowsocksr", "subscribe"}, call("subscribe"))
	entry({"admin", "services", "shadowsocksr", "component_local_status"}, call("component_local_status")).leaf = true
	entry({"admin", "services", "shadowsocksr", "component_set_mirror"}, call("component_set_mirror")).leaf = true
	entry({"admin", "services", "shadowsocksr", "component_status"}, call("component_status")).leaf = true
	entry({"admin", "services", "shadowsocksr", "component_upgrade"}, call("component_upgrade")).leaf = true
	entry({"admin", "services", "shadowsocksr", "geo_local_status"}, call("geo_local_status")).leaf = true
	entry({"admin", "services", "shadowsocksr", "geo_status"}, call("geo_status")).leaf = true
	entry({"admin", "services", "shadowsocksr", "geo_upgrade"}, call("geo_upgrade")).leaf = true
	entry({"admin", "services", "shadowsocksr", "checkport"}, call("check_port"))
	entry({"admin", "services", "shadowsocksr", "log"}, form("shadowsocksr/log"), _("Log"), 80).leaf = true
	entry({"admin", "services", "shadowsocksr", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", "shadowsocksr", "run"}, call("act_status"))
	entry({"admin", "services", "shadowsocksr", "ping"}, call("act_ping"))
	entry({"admin", "services", "shadowsocksr", "save_order"}, call("save_order")).leaf = true
	entry({"admin", "services", "shadowsocksr", "delete_node"}, call("act_delete_node")).leaf = true
	entry({"admin", "services", "shadowsocksr", "add_subscribe_item"}, call("add_subscribe_item")).leaf = true
	entry({"admin", "services", "shadowsocksr", "delete_subscribe_item"}, call("delete_subscribe_item")).leaf = true
	entry({"admin", "services", "shadowsocksr", "toggle_subscribe_item_enabled"}, call("toggle_subscribe_item_enabled")).leaf = true
	entry({"admin", "services", "shadowsocksr", "reset"}, call("act_reset"))
	entry({"admin", "services", "shadowsocksr", "restart"}, call("act_restart"))
	entry({"admin", "services", "shadowsocksr", "delete"}, call("act_delete"))
	entry({"admin", "services", "shadowsocksr", "clash_panel"}, call("clash_panel")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_groups"}, call("clash_groups")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_switch"}, call("clash_switch")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_refresh"}, call("clash_refresh")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_reset_defaults"}, call("clash_reset_defaults")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_client_policies"}, call("clash_client_policies")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_client_rule_save"}, call("clash_client_rule_save")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clash_client_rule_clear"}, call("clash_client_rule_clear")).leaf = true
	entry({"admin", "services", "shadowsocksr", "fetch_certsha256"}, call("fetch_certsha256")).leaf = true
	entry({"admin", "services", "shadowsocksr", "fetch_certbyname"}, call("fetch_certbyname")).leaf = true
	--[[Backup]]
	entry({"admin", "services", "shadowsocksr", "backup"}, call("create_backup")).leaf = true
end

function subscribe()
	nixio.fs.remove(SERVER_DETECT_CACHE)
	local sid = luci.http.formvalue("sid") or ""
	local subscribe_arg = sid ~= "" and (" " .. luci.util.shellquote(sid)) or ""
	local ret = luci.sys.call(": > /var/log/ssrplus.log && /usr/bin/lua /usr/share/shadowsocksr/subscribe.lua" .. subscribe_arg .. " >>/var/log/ssrplus.log 2>&1")
	luci.http.prepare_content("application/json")
	luci.http.write_json({ret = ret})
end

function save_order()
	local order = luci.http.formvalue("order") or ""
	local page = parse_nonnegative_int(luci.http.formvalue("page")) or 1
	local page_size = parse_nonnegative_int(luci.http.formvalue("page_size")) or 0
	local sids = {}
	local all_sections = {}
	local server_sections = {}
	local server_positions = {}
	local section_index = {}
	local page_start
	local page_end

	for sid in order:gmatch("%S+") do
		if uci:get("shadowsocksr", sid) == "servers" and not section_index[sid] then
			sids[#sids + 1] = sid
			section_index[sid] = true
		end
	end

	uci:foreach("shadowsocksr", nil, function(section)
		all_sections[#all_sections + 1] = section[".name"]
		if section[".type"] == "servers" then
			server_sections[#server_sections + 1] = section[".name"]
			server_positions[#server_positions + 1] = #all_sections
		end
	end)

	page_start = 1
	page_end = #server_sections
	if page_size > 0 then
		page_start = ((math.max(page, 1) - 1) * page_size) + 1
		page_end = math.min(page_start + page_size - 1, #server_sections)
	end

	local page_sections = {}
	local page_lookup = {}
	for index = page_start, page_end do
		local sid = server_sections[index]
		if sid then
			page_sections[#page_sections + 1] = sid
			page_lookup[sid] = true
		end
	end

	local valid = #sids > 0 and #sids == #page_sections
	if valid then
		for _, sid in ipairs(sids) do
			if not page_lookup[sid] then
				valid = false
				break
			end
		end
	end

	if valid then
		for offset, sid in ipairs(sids) do
			local absolute_index = page_start + offset - 1
			local position = server_positions[absolute_index]
			if not position then
				valid = false
				break
			end

			local cmd = string.format(
				"uci -q reorder %s=%d >/dev/null 2>&1",
				shell_quote("shadowsocksr." .. sid),
				position - 1
			)

			if luci.sys.call(cmd) ~= 0 then
				valid = false
				break
			end
			all_sections[position] = sid
		end
		if valid then
			valid = luci.sys.call("uci -q commit shadowsocksr >/dev/null 2>&1") == 0
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		ret = valid and 1 or 0,
		count = #sids,
		page = page,
		page_size = page_size
	})
end

function act_delete_node()
	local sid = luci.http.formvalue("sid")

	if not sid or sid == "" then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "missing sid" })
		return
	end

	local del_cmd = luci.sys.call("uci -q delete shadowsocksr." .. sid)
	if del_cmd ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "delete failed" })
		return
	end

	local ret_cmd = luci.sys.call("uci -q commit shadowsocksr >/dev/null 2>&1")
	if ret_cmd ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "commit failed" })
		return
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret = 1, sid = sid })
end

function add_subscribe_item()
	local sid = luci.sys.exec("uci add shadowsocksr server_subscribe_item"):gsub("%s+", "")

	if not sid or sid == "" then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "add failed" })
		return
	end

	local alias = string.format("Subscribe %s", sid:sub(-4))

	-- set enabled
	local subscribe_enabled = luci.sys.call("uci -q set shadowsocksr." .. sid .. ".enabled=1")
	if subscribe_enabled ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "set enabled failed" })
		return
	end

	-- set alias
	local subscribe_alias = luci.sys.call("uci -q set shadowsocksr." .. sid .. ".alias='" .. alias .. "'")
	if subscribe_alias ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "set alias failed" })
		return
	end

	local commit_subscribe = luci.sys.call("uci -q commit shadowsocksr >/dev/null 2>&1")
	if commit_subscribe ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "commit failed" })
		return
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret = 1, sid = sid, alias = alias, enabled = "1" })
end

function delete_subscribe_item()
	local sid = trim(luci.http.formvalue("sid"))
	if sid == "" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "missing sid" })
		return
	end

	local delete_subscribe_set = luci.sys.call("uci -q delete shadowsocksr." .. sid .. " 2>/dev/null")
	if delete_subscribe_set ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "delete failed" })
		return
	end

	-- commit
	local delete_subscribe_cmd = luci.sys.call("uci -q commit shadowsocksr >/dev/null 2>&1")
	if delete_subscribe_cmd ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "commit failed" })
		return
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret = 1, sid = sid })
end

function toggle_subscribe_item_enabled()
	local sid = trim(luci.http.formvalue("sid"))
	local field = luci.http.formvalue("field")
	local value = luci.http.formvalue("value")

	-- 兼容旧调用方式（只传 enabled）
	if not field then
		field = "enabled"
		value = luci.http.formvalue("enabled") == "1" and "1" or "0"
	end

	-- 参数校验
	if sid == "" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "missing sid" })
		return
	end

	-- 检查 sid 对应的 section 类型
	if uci:get("shadowsocksr", sid) ~= "server_subscribe_item" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "invalid_sid" })
		return
	end

	-- 白名单：只允许以下字段
	local allowed_fields = { enabled = true, alias = true, url = true }
	if not allowed_fields[field] then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "unsupported field" })
		return
	end

	-- 处理字段值
	if field == "enabled" then
		value = (value == "1" or value == "true") and "1" or "0"
	elseif field == "alias" or field == "url" then
		value = value and trim(value) or ""
	end

	-- 转义 value 中的单引号（避免破坏 uci 命令）
	local escaped_value = value:gsub("'", "'\\''")

	-- 使用外部 uci 命令设置值
	local set_cmd = string.format("uci -q set shadowsocksr.%s.%s='%s'", sid, field, escaped_value)
	local set_ret = luci.sys.call(set_cmd .. " >/dev/null 2>&1")
	if set_ret ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "uci set failed" })
		return
	end

	-- 提交更改
	local ret_cmd = luci.sys.call("uci -q commit shadowsocksr >/dev/null 2>&1")
	if ret_cmd ~= 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ ret = 0, error = "commit failed" })
		return
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret = 1, sid = sid, field = field, value = value })
end

function component_status()
	local component = luci.http.formvalue("component")
	local data, status, err = read_component_state(component, "info")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_component_json({component = component, error = err or "bad_request"})
		return
	end
	write_component_json(data)
end

function component_local_status()
	local component = luci.http.formvalue("component")
	local data, status, err = read_component_state(component, "local_info")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_component_json({component = component, error = err or "bad_request"})
		return
	end
	write_component_json(data)
end

function component_set_mirror()
	local mirror = luci.http.formvalue("mirror") or "direct"
	local allowed = {
		direct = true,
		ghproxy = true,
		ghproxy_cc = true,
		ghfast = true,
		jsdelivr = true
	}

	if not allowed[mirror] then
		mirror = "direct"
	end

	uci:set("shadowsocksr", "@global[0]", "component_mirror", mirror)
	uci:commit("shadowsocksr")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret = 1, mirror = mirror })
end

function component_upgrade()
	local component = luci.http.formvalue("component")
	local data, status, err = read_component_state(component, "upgrade")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_component_json({component = component, error = err or "bad_request", success = "0"})
		return
	end

	local info = read_component_state(component, "info")
	if info then
		for key, value in pairs(info) do
			if data[key] == nil or data[key] == "" then
				data[key] = value
			end
		end
		if data.success == "1" then
			data.can_upgrade = info.can_upgrade
		end
	end

	write_component_json(data)
end

function geo_status()
	local component = luci.http.formvalue("component")
	local data, status, err = read_geo_state(component, "info")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_geo_json({component = component, error = err or "bad_request"})
		return
	end
	write_geo_json(data)
end

function geo_local_status()
	local component = luci.http.formvalue("component")
	local data, status, err = read_geo_state(component, "local_info")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_geo_json({component = component, error = err or "bad_request"})
		return
	end
	write_geo_json(data)
end

function geo_upgrade()
	local component = luci.http.formvalue("component")
	local data, status, err = read_geo_state(component, "upgrade")
	if not data then
		luci.http.status(status or 500, "Bad Request")
		write_geo_json({component = component, error = err or "bad_request", success = "0"})
		return
	end
	write_geo_json(data)
end

function act_status()
	local e = {}
	e.running = global_client_running()
	if e.running then
		e.status_text = get_running_status_text()
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function clash_panel()
	local sid = luci.http.formvalue("sid")
	if uci:get("shadowsocksr", sid) ~= "servers" or uci:get("shadowsocksr", sid, "type") ~= "clash" then
		luci.http.status(404, "Not Found")
		return
	end
	luci.template.render("shadowsocksr/clash_panel", {
		sid = sid,
		alias = uci:get("shadowsocksr", sid, "alias") or sid
	})
end

function clash_groups()
	local sid = luci.http.formvalue("sid")
	local groups = {}
	local active_sid = resolve_active_clash_sid(sid)
	local active = active_sid ~= nil
	if active then
		local raw = clash_api_request(active_sid, "GET", "/proxies")
		if raw then
			groups = parse_clash_groups(raw.body)
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		active = active,
		sid = active_sid,
		groups = groups
	})
end

function clash_switch()
	local sid = luci.http.formvalue("sid")
	local group = luci.http.formvalue("group")
	local name = luci.http.formvalue("name")
	if not sid or not group or not name then
		luci.http.status(400, "Bad Request")
		return
	end
	local active_sid = resolve_active_clash_sid(sid)
	if not active_sid then
		luci.http.status(409, "Conflict")
		luci.http.prepare_content("application/json")
		luci.http.write_json({success = false, message = "inactive"})
		return
	end
	local body = string.format('{"name":"%s"}', tostring(name):gsub('"', '\\"'))
	local path = "/proxies/" .. urlencode(group)
	local ret = clash_api_request(active_sid, "PUT", path, body)
	luci.http.prepare_content("application/json")
	luci.http.write_json({success = ret ~= nil and ret.code and ret.code >= 200 and ret.code < 300, sid = active_sid})
end

function clash_refresh()
	local sid = luci.http.formvalue("sid")
	if not sid or uci:get("shadowsocksr", sid) ~= "servers" or uci:get("shadowsocksr", sid, "type") ~= "clash" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({success = false})
		return
	end
	local cmd = string.format("/etc/init.d/shadowsocksr clash_cache %s >/dev/null 2>&1", luci.util.shellquote(sid))
	local ok = luci.sys.call(cmd) == 0
	local reapplied = false
	if ok and is_active_clash_node(sid) then
		luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
		reapplied = true
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		success = ok,
		cached = nixio.fs.access(get_clash_cache_file(sid)),
		reapplied = reapplied
	})
end

function clash_reset_defaults()
	local sid = luci.http.formvalue("sid")
	if not sid or uci:get("shadowsocksr", sid) ~= "servers" or uci:get("shadowsocksr", sid, "type") ~= "clash" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({success = false})
		return
	end

	local state_file = get_clash_state_file(sid)
	local cleared = false
	if nixio.fs.access(state_file) then
		cleared = nixio.fs.remove(state_file) or false
	else
		cleared = true
	end

	local reapplied = false
	if cleared and is_active_clash_node(sid) then
		luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
		reapplied = true
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		success = cleared,
		reapplied = reapplied
	})
end

function clash_client_policies()
	local sid = luci.http.formvalue("sid")
	local active_sid = resolve_active_clash_sid(sid)
	local groups = {}
	if active_sid then
		local raw = clash_api_request(active_sid, "GET", "/proxies")
		if raw then
			groups = parse_clash_groups(raw.body)
		end
	end

	local policies = {}
	local seen = {}
	for _, group in ipairs(groups or {}) do
		if group.name and not seen[group.name] then
			seen[group.name] = true
			policies[#policies + 1] = {
				name = group.name,
				label = group.name,
				type = group.type or ""
			}
		end
		for _, proxy_name in ipairs(group.all or {}) do
			if proxy_name and proxy_name ~= "" and not seen[proxy_name] then
				seen[proxy_name] = true
				policies[#policies + 1] = {
					name = proxy_name,
					label = proxy_name,
					type = "proxy"
				}
			end
		end
	end

	table.sort(policies, function(a, b)
		return tostring(a.label or a.name) < tostring(b.label or b.name)
	end)

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		active = active_sid ~= nil,
		sid = active_sid,
		clients = collect_lan_clients(),
		rules = read_clash_client_rules(sid),
		policies = policies
	})
end

function clash_client_rule_save()
	local sid = luci.http.formvalue("sid")
	local rows = {}
	local max_rows = tonumber(luci.http.formvalue("count") or "0") or 0

	for index = 1, math.min(max_rows, 256) do
		local prefix = string.format("rule_%d_", index)
		local ip_addr = normalize_client_ip(luci.http.formvalue(prefix .. "ip_addr"))
		local enabled = luci.http.formvalue(prefix .. "enabled") == "1" and "1" or "0"
		local remarks = trim(luci.http.formvalue(prefix .. "remarks"))
		local policy_group = trim(luci.http.formvalue(prefix .. "policy_group"))
		local client_mac = sanitize_mac(luci.http.formvalue(prefix .. "client_mac"))

		if ip_addr ~= "" and policy_group ~= "" then
			rows[#rows + 1] = {
				enabled = enabled,
				remarks = remarks,
				ip_addr = ip_addr,
				client_mac = client_mac,
				policy_group = policy_group
			}
		end
	end

	if not sid or sid == "" or uci:get("shadowsocksr", sid) ~= "servers" or uci:get("shadowsocksr", sid, "type") ~= "clash" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ success = false, error = "invalid_sid" })
		return
	end

	write_clash_client_rules_csv(sid, rows)

	local active_sid = resolve_active_clash_sid(sid)
	local current_sid = uci:get_first("shadowsocksr", "global", "global_server")
	local reapplied = false
	if sid and sid ~= "" and uci:get("shadowsocksr", sid) == "servers"
		and uci:get("shadowsocksr", sid, "type") == "clash"
		and current_sid == sid then
		luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
		reapplied = true
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		success = true,
		count = #rows,
		reapplied = reapplied,
		rules = read_clash_client_rules(sid)
	})
end

function clash_client_rule_clear()
	local sid = luci.http.formvalue("sid")

	if not sid or sid == "" or uci:get("shadowsocksr", sid) ~= "servers" or uci:get("shadowsocksr", sid, "type") ~= "clash" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write_json({ success = false, error = "invalid_sid" })
		return
	end

	local csv_path = get_clash_client_rule_csv_path(sid)
	if csv_path and nixio.fs.access(csv_path) then
		nixio.fs.remove(csv_path)
	end

	local current_sid = uci:get_first("shadowsocksr", "global", "global_server")
	local reapplied = false
	if sid and sid ~= "" and uci:get("shadowsocksr", sid) == "servers"
		and uci:get("shadowsocksr", sid, "type") == "clash"
		and current_sid == sid then
		luci.sys.call("/etc/init.d/shadowsocksr restart >/dev/null 2>&1 &")
		reapplied = true
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		success = true,
		reapplied = reapplied,
		rules = {}
	})
end

function fetch_certsha256()
	local function fetch_cert_sha256(host, port, sni, timeout)
		if not host then return "" end
		port = tonumber(port) or 443
		sni = sni or host
		timeout = tonumber(timeout) or 5
        
		local cmd = string.format(
			"timeout %d openssl s_client -connect %s:%d -servername %s -showcerts </dev/null 2>/dev/null " ..
			"| awk 'BEGIN{c=0}/BEGIN CERT/{c++} c==1{print} /END CERT/{if(c==1)exit}' " ..
			"| openssl x509 -outform der 2>/dev/null " ..
			"| sha256sum 2>/dev/null",
			timeout, host, port, sni
		)
        
		local out = trim(luci.sys.exec(cmd))

		local fp = out:match("^([0-9a-fA-F]+)")
		if not fp or fp:lower():match("^e3b0c44298fc1c149afbf4c8996fb924") then
			return ""
		end
		return fp:upper()
	end

	local sid = luci.http.formvalue("sid") or ""
	local address = (sid ~= "") and uci:get("shadowsocksr", sid, "server") or ""
	local port_raw = (sid ~= "") and uci:get("shadowsocksr", sid, "server_port") or ""
	local port = tonumber(port_raw) or 0
	local sni = (id ~= "") and uci:get("shadowsocksr", sid, "tls_host") or ""
	sni = (sni and sni ~= "") and sni or address
	if address == "" or port == 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ code = 0, msg = "Address or Port is invalid" })
		return
	end
	local data = fetch_cert_sha256(address, port, sni, 5)
	luci.http.prepare_content("application/json")
	luci.http.write_json(data ~= "" and { code = 1, data = data } or { code = 0 })
end

function fetch_certbyname()
	local function fetch_cert_byname(host, port, sni, timeout)
		if not host then return "" end
		port = tonumber(port) or 443
		sni = sni or host
		timeout = tonumber(timeout) or 5
        
		local cmd = string.format(
			"timeout %d openssl s_client -connect %s:%d -servername %s -showcerts </dev/null 2>/dev/null " ..
			"| openssl x509 -noout -subject 2>/dev/null " ..
			"| awk '{gsub(/^.*=[[:space:]]*/, \"\"); gsub(/,.*$/, \"\"); print}'",
			timeout, host, port, sni
		)
        
		local out = trim(luci.sys.exec(cmd))
        
		if out == "" then
			return ""
		end
		return out
	end

	local sid = luci.http.formvalue("sid") or ""
	local address = (sid ~= "") and uci:get("shadowsocksr", sid, "server") or ""
	local port_raw = (sid ~= "") and uci:get("shadowsocksr", sid, "server_port") or ""
	local port = tonumber(port_raw) or 0
	local sni = (id ~= "") and uci:get("shadowsocksr", sid, "tls_host") or ""
	sni = (sni and sni ~= "") and sni or address
	if address == "" or port == 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ code = 0, msg = "Address or Port is invalid" })
		return
	end
	local data = fetch_cert_byname(address, port, sni, 5)
	luci.http.prepare_content("application/json")
	luci.http.write_json(data ~= "" and { code = 1, data = data } or { code = 0 })
end

function act_ping()
	local e = {}
	local domain = luci.http.formvalue("domain")
	local port = tonumber(luci.http.formvalue("port") or 0)
	local transport = (luci.http.formvalue("transport") or ""):lower()
	local wsPath = luci.http.formvalue("wsPath") or ""
	local host = luci.http.formvalue("host") or ""
	local tls_host = luci.http.formvalue("tlsHost") or ""
	local tls = luci.http.formvalue("tls")
	local type = (luci.http.formvalue("type") or ""):lower()
	local proto = (luci.http.formvalue("proto") or ""):lower()
	local reality = luci.http.formvalue("reality")
	local sid = luci.http.formvalue("sid")
	e.index = luci.http.formvalue("index")

	if sid and sid ~= "" and uci:get("shadowsocksr", sid) == "servers" then
		domain = uci:get("shadowsocksr", sid, "server") or domain
		port = tonumber(uci:get("shadowsocksr", sid, "server_port") or port or 0)
		transport = (uci:get("shadowsocksr", sid, "transport") or transport or ""):lower()
		wsPath = uci:get("shadowsocksr", sid, "ws_path") or wsPath
		host = uci:get("shadowsocksr", sid, "ws_host") or host
		tls_host = uci:get("shadowsocksr", sid, "tls_host") or tls_host
		tls = uci:get("shadowsocksr", sid, "tls") or tls
		type = (uci:get("shadowsocksr", sid, "type") or type or ""):lower()
		proto = (uci:get("shadowsocksr", sid, "v2ray_protocol") or proto or ""):lower()
		reality = uci:get("shadowsocksr", sid, "reality") or reality
	end

	local is_ip = domain and domain:match("^%d+%.%d+%.%d+%.%d+$")
	local probe_host = (tls_host ~= "" and tls_host) or (host ~= "" and host) or domain
	local is_reality = (reality == "1" or reality == "true")
	local prefers_handshake_latency = (type == "v2ray") and not is_reality

	-- 临时放行防火墙逻辑
	local use_nft = use_fw4_backend()
	local iret = false
	if domain then
		if use_nft then
			iret = luci.sys.call("nft add element inet ss_spec ss_spec_wan_ac { " .. domain .. " } 2>/dev/null") == 0
		else
			iret = luci.sys.call("ipset add ss_spec_wan_ac " .. domain .. " 2>/dev/null") == 0
		end
	end
	-- Hysteria2 节点轻量 UDP 端口检测
	if proto:find("hysteria2") or type:find("hysteria2") then
		local udp_cmd = string.format("nping --udp -c 1 -p %d %s 2>/dev/null", port, domain)
		local udp_raw = luci.sys.exec(udp_cmd) or ""
		local udp_rtt = udp_raw:match("Avg rtt:%s*([0-9.]+)ms")
		local udp_unreachable = udp_raw:match("[Pp]ort [Uu]nreachable") or udp_raw:match("ICMP")
		local udp_sent = udp_raw:match("Raw packets sent:%s*1")

		-- UDP 服务通常不会主动回包，未收到应答不等于端口不可用。
		-- 仅在出现明显的不可达迹象时标记 fail，其余视为轻量可达。
		e.socket = (udp_unreachable == nil) and (udp_sent ~= nil)
		e.ping = udp_rtt and normalize_ping_ms(udp_rtt) or nil

		if not e.ping then
			local icmp_cmd = string.format("ping -c 1 -W 1 %s 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2", domain)
			e.ping = normalize_ping_ms(tonumber(luci.sys.exec(icmp_cmd)))
		end
		if not e.ping then
			e.ping = 0
		end
	elseif transport == "ws" then
		-- WebSocket 探测
		local result = ""
		local success = false
		local icmp_cmd = string.format("ping -c 1 -W 1 %s 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2", domain)
		e.ping = normalize_ping_ms(tonumber(luci.sys.exec(icmp_cmd)))
		-- WebSocket 探测 (适用于域名，或带 SNI 的 IP)
		if not is_ip or probe_host ~= domain then
			local resolve_arg = ""
			local final_domain = probe_host
			if is_ip and probe_host and probe_host ~= "" then
				-- IP 模式下使用 --resolve 强制指定 SNI，解决 TLS 握手失败
				resolve_arg = string.format("--resolve '%s:%d:%s' ", probe_host, port, domain)
			end
			local prefix = (tls == '1') and "https://" or "http://"
			local address = prefix .. final_domain .. ':' .. port .. wsPath
			local cmd = string.format(
				"curl --http1.1 -m 2 -ksN -o /dev/null %s" ..
				"-w 'time_connect=%%{time_connect}\\nhttp_code=%%{http_code}' " ..
				"%s" ..
				"-H 'Connection: Upgrade' -H 'Upgrade: websocket' " ..
				"-H 'Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==' " ..
				"-H 'Sec-WebSocket-Version: 13' '%s'",
				resolve_arg,
				(probe_host and probe_host ~= "") and ("-H " .. luci.util.shellquote("Host: " .. probe_host) .. " ") or "",
				address
			)
			result = luci.sys.exec(cmd) or ""
			success = (string.match(result, "http_code=(%d+)") == "101")
		end
		-- 如果深度探测失败，或是不支持深测的纯 IP
		if not success then
			local socket = nixio.socket("inet", "stream")
			if socket then
				socket:setopt("socket", "rcvtimeo", 3)
				socket:setopt("socket", "sndtimeo", 3)
				success = socket:connect(domain, port)
				socket:close()
			end
			--luci.sys.exec(string.format("echo 'Node %s (ws) failed deep test, using TCP fallback' >> /tmp/ping.log", domain))
		end
		e.socket = success
		-- 延迟：优先 ping，再 curl，最后 nping tcp-connect
		if not e.ping then
			local ping_time = tonumber(string.match(result, "time_connect=(%d+.%d%d%d)"))
			local appconnect_time = tonumber(string.match(result, "time_appconnect=(%d+.%d%d%d)"))
			if appconnect_time and appconnect_time > 0 then
				e.ping = normalize_ping_ms(appconnect_time, 1000)
			elseif ping_time and ping_time > 0 then
				e.ping = normalize_ping_ms(ping_time, 1000)
			else
				e.ping = detect_tcp_connect_ms(domain, port) or 0
			end
		end
	else
		-- 3. 非 WebSocket 节点的探测逻辑 (TCP / ICMP / UDP)
		local socket = nixio.socket("inet", "stream")
		if socket then
			socket:setopt("socket", "rcvtimeo", 3)
			socket:setopt("socket", "sndtimeo", 3)
			e.socket = socket:connect(domain, port)
			socket:close()
		end

		if prefers_handshake_latency and (tls == "1" or tls_host ~= "" or proto == "vless" or proto == "vmess") then
			e.ping = detect_tls_handshake_ms(domain, port, "", probe_host, domain, false)
		end

		-- 延迟：优先真实握手，再 nping tcp-connect -> ping -> nping(udp)
		if not e.ping then
			if not is_reality then
				e.ping = detect_tcp_connect_ms(domain, port)
			end
		end
		if not e.ping then
			local icmp_cmd = string.format("ping -c 1 -W 1 %s 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2", domain)
			e.ping = normalize_ping_ms(tonumber(luci.sys.exec(icmp_cmd)))
		end

		if not e.ping then
			local udp_cmd = string.format("nping --udp -c 1 -p %d %s 2>/dev/null | grep -o 'Avg rtt: [0-9.]*ms' | awk '{print $3}' | sed 's/ms//' | head -1", port, domain)
			local udp_res = luci.sys.exec(udp_cmd)
			if udp_res and udp_res ~= "" then
				local ping_num = tonumber(udp_res)
				if ping_num then e.ping = normalize_ping_ms(ping_num) end
			end
		end

		if (not e.ping or e.ping == 0) and domain and port > 0 then
			local schemes = { "https", "http" }
			for _, scheme in ipairs(schemes) do
				local connect_cmd = string.format(
					"curl -m 2 -ksS -o /dev/null -w 'time_connect=%%{time_connect}' %s://%s:%d 2>/dev/null",
					scheme, domain, port
				)
				local connect_res = luci.sys.exec(connect_cmd) or ""
				local connect_time = tonumber(connect_res:match("time_connect=([0-9.]+)"))
				if connect_time and connect_time > 0 then
					e.ping = normalize_ping_ms(connect_time, 1000)
					break
				end
			end
		end
	end

	-- 4. 清理防火墙规则
	if iret then
		if use_nft then
			luci.sys.call("nft delete element inet ss_spec ss_spec_wan_ac { " .. domain .. " } 2>/dev/null")
		else
			luci.sys.call("ipset del ss_spec_wan_ac " .. domain .. " 2>/dev/null")
		end
	end

	if sid and sid ~= "" then
		save_detect_cache_entry(sid, {
			server = domain or "",
			port = port or 0,
			type = type or "",
			proto = proto or "",
			socket = e.socket and true or false,
			ping = tonumber(e.ping) or 0,
			time = os.time()
		})
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function check_status()
	local e = {}
	local target = luci.http.formvalue("set") or ""
	e.ret = luci.sys.call("curl -m 3 -sS -o /dev/null http://www." .. target .. ".com >/dev/null 2>&1")
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function refresh_data()
	local set = luci.http.formvalue("set")
	local retstring = loadstring("return " .. luci.sys.exec("/usr/bin/lua /usr/share/shadowsocksr/update.lua " .. set))()
	luci.http.prepare_content("application/json")
	luci.http.write_json(retstring)
end

function check_port()
	local retstring = "<br /><br />"
	local s
	local server_name = ""
	local uci = require "luci.model.uci".cursor()
	local use_nft = use_fw4_backend()

	uci:foreach("shadowsocksr", "servers", function(s)
		if s.type == "clash" then
			retstring = retstring .. string.format("<font><b style='color:gray'>[%s] Clash panel node.</b></font><br />", s.alias or s[".name"])
			return
		end
		if s.alias then
			server_name = s.alias
		elseif s.server and s.server_port then
			server_name = s.server .. ":" .. s.server_port
		end

		-- 临时加入 set
		local is_ipv6 = is_ipv6_address(s.server)
		local iret = false
		if not is_ipv6 then
			if use_nft then
				iret = luci.sys.call("nft add element inet ss_spec ss_spec_wan_ac { " .. s.server .. " } 2>/dev/null") == 0
			else
				iret = luci.sys.call("ipset add ss_spec_wan_ac " .. s.server .. " 2>/dev/null") == 0
			end
		end

		-- TCP 测试
		local socket = nixio.socket(is_ipv6 and "inet6" or "inet", "stream")
		socket:setopt("socket", "rcvtimeo", 3)
		socket:setopt("socket", "sndtimeo", 3)
		local ret = socket:connect(s.server, s.server_port)
		socket:close()

		if ret then
			retstring = retstring .. string.format("<font><b style='color:green'>[%s] OK.</b></font><br />", server_name)
		else
			retstring = retstring .. string.format("<font><b style='color:red'>[%s] Error.</b></font><br />", server_name)
		end

		-- 删除临时 set
		if iret then
			if use_nft then
				luci.sys.call("nft delete element inet ss_spec ss_spec_wan_ac { " .. s.server .. " } 2>/dev/null")
			else
				luci.sys.call("ipset del ss_spec_wan_ac " .. s.server)
			end
		end
	end)

	luci.http.prepare_content("application/json")
	luci.http.write_json({ret = retstring})
end

function act_reset()
	luci.sys.call("/etc/init.d/shadowsocksr reset >/dev/null 2>&1")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr"))
end

function act_restart()
	luci.sys.call("/etc/init.d/shadowsocksr restart > /dev/null 2>&1 &")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr"))
end

function act_delete()
	luci.sys.call("/etc/init.d/shadowsocksr restart > /dev/null 2>&1 &")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers"))
end

function get_log()
	luci.http.write(luci.sys.exec("[ -f '/var/log/ssrplus.log' ] && cat /var/log/ssrplus.log"))
end
	
function clear_log()
	luci.sys.call("echo '' > /var/log/ssrplus.log")
end

function create_backup()
	local backup_files = {
		"/etc/config/shadowsocksr",
		"/etc/ssrplus/*"
	}
	local date = os.date("%Y-%m-%d-%H-%M-%S")
	local tar_file = "/tmp/shadowsocksr-" .. date .. "-backup.tar.gz"
	nixio.fs.remove(tar_file)
	local cmd = "tar -czf " .. tar_file .. " " .. table.concat(backup_files, " ")
	luci.sys.call(cmd)
	luci.http.header("Content-Disposition", "attachment; filename=shadowsocksr-" .. date .. "-backup.tar.gz")
	luci.http.header("X-Backup-Filename", "shadowsocksr-" .. date .. "-backup.tar.gz")
	luci.http.prepare_content("application/octet-stream")
	luci.http.write(nixio.fs.readfile(tar_file))
	nixio.fs.remove(tar_file)
end
