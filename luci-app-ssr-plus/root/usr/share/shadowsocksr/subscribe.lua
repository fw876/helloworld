#!/usr/bin/lua

------------------------------------------------
-- This file is part of the luci-app-ssr-plus subscribe.lua
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require "luci.model.uci"
require "nixio"
require "luci.util"
require "luci.sys"
require "luci.jsonc"

-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local jsonParse, jsonStringify = luci.jsonc.parse, luci.jsonc.stringify
local b64decode = nixio.bin.b64decode
local b64encode = nixio.bin.b64encode
local URL = require "url"
local cache = {}
local nodeResult = setmetatable({}, {__index = cache}) -- update result
local name = 'shadowsocksr'
local uciType = 'servers'
local ucic = require "luci.model.uci".cursor()
local proxy = ucic:get_first(name, 'server_subscribe', 'proxy', '0')
local switch = ucic:get_first(name, 'server_subscribe', 'switch', '1')
local allow_insecure = ucic:get_first(name, 'server_subscribe', 'allow_insecure', '0')
local filter_words = ucic:get_first(name, 'server_subscribe', 'filter_words', '过期/重置/套餐/剩余/网址/QQ群/官网/防失联/回国')
local save_words = ucic:get_first(name, 'server_subscribe', 'save_words', '')
local user_agent = ucic:get_first(name, 'server_subscribe', 'user_agent', 'v2rayN/9.99')
-- 读取 enable_mihomo 配置
local enable_mihomo = ucic:get_first(name, 'server_subscribe', 'enable_mihomo', '')
local sub_convert = ucic:get_first(name, 'server_subscribe', 'sub_convert', '0')
local convert_address = ucic:get_first(name, 'server_subscribe', 'convert_address', 'https://api.asailor.org/sub')
local template_url = ucic:get_first(name, 'server_subscribe', 'template_url', '')
local local_clash_dir = "/etc/ssrplus/clash"
local target_subscribe_sid = tostring(arg and arg[1] or ""):gsub("^%s*(.-)%s*$", "%1")

local has_ss_rust = luci.sys.exec('type -t -p sslocal 2>/dev/null || type -t -p ssserver 2>/dev/null') ~= ""
local has_xray = luci.sys.exec('type -t -p xray 2>/dev/null') ~= ""
local has_mihomo = luci.sys.exec('type -t -p mihomo -p /usr/libexec/mihomo 2>/dev/null') ~= ""

local tuic_type = luci.sys.exec('type -t -p mihomo -p /usr/libexec/mihomo 2>/dev/null') ~= "" and "tuic"
local log = function(...)
	print(os.date("%Y-%m-%d %H:%M:%S ") .. table.concat({...}, " "))
end

-- 检查是否需要使用 Mihomo 订阅模式
local function should_use_mihomo_mode()
	-- 如果 enable_mihomo == 1，使用 Mihomo 模式
	if enable_mihomo == "1" and has_mihomo then
		return true
	end
	-- 如果 enable_mihomo ~= 1，检查是否有其他可用核心
	if enable_mihomo ~= "1" then
		-- 有其他核心可用，使用传统模式
		if has_xray or has_ss_rust then
			return false
		end
		-- 没有其他核心，回退到 Mihomo 模式
		if has_mihomo then
			log("回退: Xray/ss-rust 不存在，使用 Mihomo 订阅模式")
			return true
		end
	end
	-- 默认：如果有 Mihomo 则使用 Mihomo 模式
	return has_mihomo
end

local function preferred_ss_backend()
	if should_use_mihomo_mode() and has_mihomo then
		return "ss"
	end
	if has_ss_rust then
		return "ss-rust"
	end
	if has_xray then
		return "v2ray"
	end
	if has_mihomo then
		return "ss"
	end
	return nil
end

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

-- 分割字符串
local function split(full, sep)
	if full == nil or type(full) ~= "string" then
		-- print("Debug: split() received nil or non-string value")
		return {}
	end
	full = full:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "") -- 去除首尾空白字符和\0
	if full == "" then
		-- print("Debug: split() received empty string after trimming")
		return {}
	end
	sep = sep or "," -- 默认分隔符
	local off, result = 1, {}
	while true do
		local nStart, nEnd = full:find(sep, off)
		if not nEnd then
			local res = ssub(full, off, slen(full))
			if #res > 0 then -- 过滤掉 \0
				tinsert(result, res)
			end
			break
		else
			tinsert(result, ssub(full, off, nStart - 1))
			off = nEnd + 1
		end
	end
	return result
end

-- urlencode
local function get_urlencode(c)
	return sformat("%%%02X", sbyte(c))
end

local function urlEncode(szText)
	local str = szText:gsub("([^0-9a-zA-Z ])", get_urlencode)
	str = str:gsub(" ", "+")
	return str
end

local function urlEncodeRFC3986(szText)
	local str = tostring(szText or ""):gsub("([^0-9a-zA-Z%-_%.~])", get_urlencode)
	return str
end

local function get_urldecode(h)
	return schar(tonumber(h, 16))
end

local function UrlDecode(szText)
	return szText:gsub("+", " "):gsub("%%(%x%x)", get_urldecode)
end

-- trim
local function trim(text)
	if not text or text == "" then
		return ""
	end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end

local function shell_quote(value)
	value = tostring(value or "")
	return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function nft_string_literal(value)
	value = tostring(value or "")
	value = value:gsub("\\", "\\\\"):gsub('"', '\\"')
	return '"' .. value .. '"'
end

local function escape_lua_pattern(value)
	return tostring(value or ""):gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1")
end

local function is_true_value(v)
	if v == nil then
		return false
	end
	if v == true then
		return true
	end
	if type(v) == "string" then
		local s = trim(string.lower(v))
		return s == "1" or s == "true" or s == "yes" or s == "on"
	end
	return false
end

local function collect_subscribe_items()
	local items = {}

	ucic:foreach(name, "server_subscribe_item", function(s)
		if target_subscribe_sid ~= "" and s[".name"] ~= target_subscribe_sid then
			return
		end

		local url = trim(s.url or "")
		if url == "" then
			return
		end

		if target_subscribe_sid == "" and not is_true_value(s.enabled or "1") then
			return
		end

		items[#items + 1] = {
			sid = s[".name"],
			alias = trim(s.alias or ""),
			url = url
		}
	end)

	if #items > 0 then
		return items
	end

	if target_subscribe_sid ~= "" then
		return items
	end

	local legacy_urls = ucic:get_first(name, 'server_subscribe', 'subscribe_url', {})
	for index, url in ipairs(legacy_urls or {}) do
		url = trim(url)
		if url ~= "" then
			items[#items + 1] = {
				sid = "legacy_" .. index,
				alias = "Legacy " .. index,
				url = url
			}
		end
	end

	return items
end

local subscribe_items = collect_subscribe_items()

local function first_nonempty(tbl, keys)
	for _, key in ipairs(keys) do
		local value = tbl[key]
		if value ~= nil and value ~= "" then
			return value
		end
	end
	return nil
end

local function normalize_host(value)
	value = trim(value or "")
	if value == "" then
		return value
	end
	if value:match("^%[.*%]$") then
		return value:sub(2, -2)
	end
	return value
end

local function parse_host_port(value, default_port)
	value = trim(value or "")
	if value == "" then
		return nil, default_port
	end

	local host, port = value:match("^%[(.*)%]:(%d+)$")
	if host then
		return normalize_host(host), port
	end

	host, port = value:match("^(.-):(%d+)$")
	if host and host ~= "" and not host:find(":", 1, true) then
		return normalize_host(host), port
	end

	if value:find(":", 1, true) then
		return normalize_host(value), default_port
	end

	return normalize_host(value), default_port
end

-- md5
local function md5(content)
	local stdout = luci.sys.exec('echo \"' .. urlEncode(content) .. '\" | md5sum | cut -d \" \" -f1')
	-- assert(nixio.errno() == 0)
	return trim(stdout)
end

-- base64 解码
local function base64Decode(text)
	local raw = text
	if not text or text == "" then
		return ''
	end
	text = text:gsub("%z", "")
	text = text:gsub("%c", "")
	text = text:gsub("%s", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	text = text:gsub("=", "")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end

-- base64 编码
local function base64Encode(text)
	if not text or text == "" then
		return ''
	end
	local result = b64encode(text)
	if result then
		result = result:gsub("%z", "")
		return result
	else
		return text
	end
end

-- 检查数组(table)中是否存在某个字符值
-- https://www.04007.cn/article/135.html
local function checkTabValue(tab)
	local revtab = {}
	for k,v in pairs(tab) do
		revtab[v] = true
	end
	return revtab
end

-- JSON完整性检查
local function isCompleteJSON(str)
	-- 检查JSON格式
	if type(str) ~= "string" or str:match("^%s*$") then
        return false
    end
	-- 尝试解析JSON验证完整性
	local success, _ = pcall(jsonParse, str)
	return success
end

local function isClashYAML(str)
	if type(str) ~= "string" or str:match("^%s*$") then
		return false
	end

	for line in str:gmatch("[^\r\n]+") do
		if line:match("^%s*proxies%s*:") or line:match("^%s*proxy%-providers%s*:") then
			return true
		end
	end

	return false
end

local function processClashSubscription(url)
	local ok, parsed = pcall(URL.parse, url)
	if not ok or not parsed or not parsed.host then
		return nil
	end

	local url_hash = string.sub(md5(url), 1, 8)
	local alias = "Clash_" .. parsed.host .. "_" .. url_hash
	local server_port = parsed.port or ((parsed.scheme == "http") and "80" or "443")
	local result = {
		type = "clash",
		server = normalize_host(parsed.host),
		server_port = server_port,
		clash_url = url,
		clash_user_agent = user_agent,
		raw_alias = alias,
		alias = alias
	}

	local saved_alias = result.alias
	result.alias = nil
	result.hashkey = md5(jsonStringify(result) .. "_" .. (saved_alias or ""))
	result.alias = saved_alias
	return result
end

local function yaml_quote(str)
	str = tostring(str or "")
	str = str:gsub("\\", "\\\\"):gsub('"', '\\"')
	return '"' .. str .. '"'
end

local function is_ip_literal(value)
	if not value or value == "" then
		return false
	end

	if value:match("^%d+%.%d+%.%d+%.%d+$") then
		return true
	end

	return value:find(":", 1, true) ~= nil
end

local function parseAnytlsShare(content)
	local alias = ""
	if content:find("#", 1, true) then
		local idx = content:find("#", 1, true)
		alias = UrlDecode(content:sub(idx + 1))
		content = content:sub(1, idx - 1)
	end

	local main, query = content, ""
	if content:find("%?", 1) then
		local idx = content:find("%?", 1)
		main = content:sub(1, idx - 1)
		query = content:sub(idx + 1)
	end

	local userinfo, hostinfo = main:match("^([^@]+)@(.+)$")
	if not userinfo or not hostinfo then
		return nil
	end
	hostinfo = hostinfo:gsub("/+$", "")

	local password = UrlDecode(userinfo)
	local server, port = hostinfo:match("^(.+):(%d+)$")
	if not server or not port then
		server = hostinfo
		port = "443"
	end
	server = server:gsub("^%[", ""):gsub("%]$", "")

	local params = {}
	for _, v in ipairs(split(query, "&")) do
		local t = split(v, "=")
		if #t > 1 then
			params[string.lower(t[1])] = UrlDecode(t[2] or "")
		end
	end

	return {
		name = (alias ~= "" and alias) or (server .. ":" .. port),
		server = server,
		port = tonumber(port),
		password = password,
		sni = (function()
			local sni = params.sni or params.servername or ""
			if is_ip_literal(sni) then
				return ""
			end
			return sni
		end)(),
		allow_insecure = (params.insecure == "1" or params.allow_insecure == "1" or params.allowinsecure == "1"),
		client_fingerprint = params.fp or params.fingerprint or ""
	}
end

local function buildAnytlsClashYaml(entries, group_name)
	local lines = {
		"mode: rule",
		"log-level: silent",
		"proxies:"
	}

	for _, node in ipairs(entries) do
		lines[#lines + 1] = "  - name: " .. yaml_quote(node.name)
		lines[#lines + 1] = "    type: anytls"
		lines[#lines + 1] = "    server: " .. yaml_quote(node.server)
		lines[#lines + 1] = "    port: " .. tostring(node.port)
		lines[#lines + 1] = "    password: " .. yaml_quote(node.password)
		if node.sni and node.sni ~= "" then
			lines[#lines + 1] = "    sni: " .. yaml_quote(node.sni)
		end
		if node.allow_insecure then
			lines[#lines + 1] = "    skip-cert-verify: true"
		end
		if node.client_fingerprint and node.client_fingerprint ~= "" then
			lines[#lines + 1] = "    client-fingerprint: " .. yaml_quote(node.client_fingerprint)
		end
	end

	lines[#lines + 1] = "proxy-groups:"
	lines[#lines + 1] = "  - name: " .. yaml_quote(group_name)
	lines[#lines + 1] = "    type: select"
	lines[#lines + 1] = "    proxies:"
	for _, node in ipairs(entries) do
		lines[#lines + 1] = "      - " .. yaml_quote(node.name)
	end
	lines[#lines + 1] = "rules:"
	lines[#lines + 1] = "  - MATCH," .. group_name

	return table.concat(lines, "\n") .. "\n"
end

local function anytls_to_mihomo_node(entry)
	if not entry then
		return nil
	end

	return {
		type = "anytls",
		alias = entry.name,
		raw_alias = entry.name,
		server = entry.server,
		server_port = entry.port,
		password = entry.password,
		tls_host = entry.sni,
		insecure = entry.allow_insecure and "1" or "0",
		fingerprint = entry.client_fingerprint
	}
end

local function split_csv_values(value)
	local items = {}
	for v in tostring(value or ""):gmatch("[^,;|%s]+") do
		items[#items + 1] = v
	end
	return items
end

local function bool_from_flag(value)
	return is_true_value(value) and true or nil
end

local function number_from_value(value)
	if value == nil or value == "" then
		return nil
	end
	return tonumber(value)
end

local function string_from_value(value)
	if value == nil or value == "" then
		return nil
	end
	return tostring(value)
end

local function split_plugin_opts(value)
	local opts = {}
	for part in tostring(value or ""):gmatch("[^;]+") do
		local key, val = part:match("^%s*([^=]+)=?(.*)%s*$")
		if key and key ~= "" then
			opts[key] = val or ""
		end
	end
	return opts
end

local function pick_plugin_opt(opts, ...)
	for i = 1, select("#", ...) do
		local key = select(i, ...)
		if opts[key] ~= nil and opts[key] ~= "" then
			return opts[key]
		end
	end
	return nil
end

local function normalize_mihomo_plugin_name(plugin)
	local value = tostring(plugin or ""):lower()
	if value == "" or value == "none" then
		return ""
	end
	if value == "simple-obfs" or value == "obfs" or value == "obfs-local" then
		return "obfs"
	end
	if value == "xray-plugin" then
		return "v2ray-plugin"
	end
	if value == "shadowtls" then
		return "shadow-tls"
	end
	return value
end

local function apply_mihomo_ss_plugin(proxy, node)
	local plugin = normalize_mihomo_plugin_name(node.plugin)
	if plugin == "" then
		return
	end

	local opts = split_plugin_opts(node.plugin_opts)
	proxy.plugin = plugin
	if plugin == "obfs" then
		proxy["plugin-opts"] = {
			mode = pick_plugin_opt(opts, "obfs", "mode") or "http",
			host = string_from_value(pick_plugin_opt(opts, "obfs-host", "obfs_host", "host"))
		}
	elseif plugin == "shadow-tls" then
		proxy["client-fingerprint"] = string_from_value(node.fingerprint)
		proxy["plugin-opts"] = {
			host = string_from_value(pick_plugin_opt(opts, "host")),
			password = string_from_value(pick_plugin_opt(opts, "passwd", "password")),
			version = number_from_value(pick_plugin_opt(opts, "version")) or (opts.v3 == "1" and 3) or (opts.v2 == "1" and 2) or (opts.v1 == "1" and 1) or nil
		}
	elseif plugin == "v2ray-plugin" then
		proxy["plugin-opts"] = {
			mode = pick_plugin_opt(opts, "mode") or "websocket",
			tls = bool_from_flag(pick_plugin_opt(opts, "tls")),
			host = string_from_value(pick_plugin_opt(opts, "host")),
			path = string_from_value(pick_plugin_opt(opts, "path")),
			mux = bool_from_flag(pick_plugin_opt(opts, "mux")),
			["skip-cert-verify"] = bool_from_flag(pick_plugin_opt(opts, "skip-cert-verify", "skip_cert_verify", "insecure")),
			["v2ray-http-upgrade"] = bool_from_flag(pick_plugin_opt(opts, "v2ray-http-upgrade", "v2ray_http_upgrade"))
		}
	else
		proxy["plugin-opts"] = next(opts) and opts or nil
	end
end

local function apply_mihomo_tls_options(proxy, node)
	local tls_enabled = node.tls == "1" or node.reality == "1"
	if not tls_enabled then
		return
	end

	proxy.tls = true
	proxy.servername = string_from_value(node.tls_host)
	proxy.fingerprint = string_from_value(node.tls_CertSha)
	proxy["client-fingerprint"] = string_from_value(node.fingerprint)
	proxy["skip-cert-verify"] = bool_from_flag(node.insecure)

	local alpn = split_csv_values(node.tls_alpn)
	if #alpn > 0 then
		proxy.alpn = alpn
	end

	if node.reality == "1" then
		proxy["reality-opts"] = {
			["public-key"] = string_from_value(node.reality_publickey),
			["short-id"] = string_from_value(node.reality_shortid),
			["support-x25519mlkem768"] = bool_from_flag(node.enable_mldsa65verify)
		}
	end

	if node.enable_ech == "1" and node.ech_config and node.ech_config ~= "" then
		proxy["ech-opts"] = {
			enable = true,
			config = node.ech_config
		}
	end
end

local function apply_mihomo_trojan_tls_options(proxy, node)
	proxy.sni = string_from_value(node.tls_host)
	proxy.fingerprint = string_from_value(node.tls_CertSha)
	proxy["client-fingerprint"] = string_from_value(node.fingerprint)
	proxy["skip-cert-verify"] = bool_from_flag(node.insecure)

	local alpn = split_csv_values(node.tls_alpn)
	if #alpn > 0 then
		proxy.alpn = alpn
	end

	if node.reality == "1" then
		proxy["reality-opts"] = {
			["public-key"] = string_from_value(node.reality_publickey),
			["short-id"] = string_from_value(node.reality_shortid)
		}
	end
end

local function apply_mihomo_transport_options(proxy, node)
	local transport = node.transport or "raw"
	if transport == "raw" or transport == "tcp" or transport == "" then
		return
	end
	if transport == "httpupgrade" then
		proxy.network = "ws"
		proxy["ws-opts"] = {
			path = string_from_value(node.httpupgrade_path),
			headers = node.httpupgrade_host and node.httpupgrade_host ~= "" and { Host = node.httpupgrade_host } or nil,
			["v2ray-http-upgrade"] = true
		}
	elseif transport == "ws" then
		proxy.network = "ws"
		proxy["ws-opts"] = {
			path = string_from_value(node.ws_path),
			headers = node.ws_host and node.ws_host ~= "" and { Host = node.ws_host } or nil
		}
	elseif transport == "h2" then
		proxy.network = "h2"
		proxy["h2-opts"] = {
			host = node.h2_host and node.h2_host ~= "" and split_csv_values(node.h2_host) or nil,
			path = string_from_value(node.h2_path)
		}
	elseif transport == "grpc" then
		proxy.network = "grpc"
		proxy["grpc-opts"] = {
			["grpc-service-name"] = string_from_value(node.serviceName)
		}
	elseif transport == "xhttp" and proxy.type == "vless" then
		proxy.network = "xhttp"
		proxy["xhttp-opts"] = {
			path = string_from_value(node.xhttp_path),
			host = string_from_value(node.xhttp_host),
			mode = string_from_value(node.xhttp_mode)
		}
	end
end

local function to_mihomo_proxy(node)
	local proxy = {
		name = node.alias,
		server = node.server,
		port = tonumber(node.server_port) or node.server_port,
		udp = true
	}

	if node.type == "v2ray" and node.v2ray_protocol == "vmess" then
		proxy.type = "vmess"
		proxy.uuid = node.vmess_id
		proxy.alterId = tonumber(node.alter_id) or 0
		proxy.cipher = node.security or "auto"
		proxy.tfo = bool_from_flag(node.fast_open)
		apply_mihomo_tls_options(proxy, node)
		apply_mihomo_transport_options(proxy, node)
	elseif node.type == "v2ray" and node.v2ray_protocol == "vless" then
		proxy.type = "vless"
		proxy.uuid = node.vmess_id
		proxy.flow = string_from_value(node.tls_flow)
		proxy.encryption = node.vless_encryption or ""
		proxy.tfo = bool_from_flag(node.fast_open)
		apply_mihomo_tls_options(proxy, node)
		apply_mihomo_transport_options(proxy, node)
	elseif node.type == "ss" or node.type == "ss-rust" or (node.type == "v2ray" and node.v2ray_protocol == "shadowsocks") then
		proxy.type = "ss"
		proxy.cipher = node.encrypt_method_ss or node.encrypt_method
		proxy.password = node.password
		proxy.tfo = bool_from_flag(node.fast_open)
		apply_mihomo_ss_plugin(proxy, node)
	elseif node.type == "ssr" then
		proxy.type = "ssr"
		proxy.cipher = node.encrypt_method
		proxy.password = node.password
		proxy.obfs = node.obfs
		proxy.protocol = node.protocol
		proxy["obfs-param"] = string_from_value(node.obfs_param)
		proxy["protocol-param"] = string_from_value(node.protocol_param)
		proxy.tfo = bool_from_flag(node.fast_open)
	elseif node.type == "v2ray" and node.v2ray_protocol == "trojan" then
		proxy.type = "trojan"
		proxy.password = node.password
		proxy.tfo = bool_from_flag(node.fast_open)
		apply_mihomo_trojan_tls_options(proxy, node)
		apply_mihomo_transport_options(proxy, node)
	elseif node.type == "tuic" then
		local alpn = split_csv_values(node.tls_alpn)
		local heartbeat = number_from_value(node.heartbeat)
		local timeout = number_from_value(node.timeout)
		proxy.type = "tuic"
		proxy.uuid = node.tuic_uuid
		proxy.password = node.tuic_passwd
		proxy.ip = string_from_value(node.tuic_ip)
		proxy.sni = string_from_value(node.tls_host)
		proxy.alpn = (#alpn > 0) and alpn or nil
		proxy["udp-relay-mode"] = string_from_value(node.udp_relay_mode)
		proxy["congestion-controller"] = string_from_value(node.congestion_control)
		proxy["heartbeat-interval"] = heartbeat and (heartbeat * 1000) or nil
		proxy["request-timeout"] = timeout and (timeout * 1000) or nil
		proxy["max-udp-relay-packet-size"] = number_from_value(node.tuic_max_package_size)
		proxy["disable-sni"] = bool_from_flag(node.disable_sni)
		proxy["reduce-rtt"] = bool_from_flag(node.zero_rtt_handshake)
		proxy["skip-cert-verify"] = bool_from_flag(node.insecure)
	elseif node.type == "v2ray" and (node.v2ray_protocol == "hysteria2" or node.v2ray_protocol == "hy2") then
		local alpn = split_csv_values(node.tls_alpn)
		proxy.type = "hysteria2"
		proxy.password = node.hy2_auth
		proxy.ports = string_from_value(node.port_range)
		proxy.up = node.uplink_capacity and (tostring(node.uplink_capacity) .. " Mbps") or nil
		proxy.down = node.downlink_capacity and (tostring(node.downlink_capacity) .. " Mbps") or nil
		proxy.sni = string_from_value(node.tls_host)
		proxy.fingerprint = string_from_value(node.tls_CertSha)
		proxy["skip-cert-verify"] = bool_from_flag(node.insecure)
		proxy.alpn = (#alpn > 0) and alpn or nil
		if node.flag_obfs == "1" then
			proxy.obfs = string_from_value(node.obfs_type)
			proxy["obfs-password"] = string_from_value(node.salamander)
		end
	elseif node.type == "anytls" then
		proxy.type = "anytls"
		proxy.password = node.password
		proxy.sni = string_from_value(node.tls_host)
		proxy["client-fingerprint"] = string_from_value(node.fingerprint)
		proxy["skip-cert-verify"] = bool_from_flag(node.insecure)
	elseif node.type == "v2ray" and node.v2ray_protocol == "snell" then
		proxy.type = "snell"
		proxy.psk = node.snell_psk
		proxy.version = tonumber(node.snell_version) or nil
		local obfs_mode = string_from_value(node.snell_obfs)
		local obfs_host = string_from_value(node.snell_obfs_host)
		if obfs_mode or obfs_host then
			proxy["obfs-opts"] = {
				mode = obfs_mode,
				host = obfs_host
			}
		end
	else
		return nil
	end

	if not proxy.name or proxy.name == "" or not proxy.server or not proxy.port then
		return nil
	end

	return proxy
end

local function can_group_into_mihomo(node)
	if not node then
		return false
	end
	-- 如果不使用 Mihomo 模式，返回 false
	if not should_use_mihomo_mode() then
		return false
	end
	if node.type == "ssr" or node.type == "ss" or node.type == "ss-rust" then
		return true
	end
	if node.type == "v2ray" and (
		node.v2ray_protocol == "vmess"
		or node.v2ray_protocol == "vless"
		or node.v2ray_protocol == "shadowsocks"
		or node.v2ray_protocol == "trojan"
		or node.v2ray_protocol == "hysteria2"
		or node.v2ray_protocol == "hy2"
		or node.v2ray_protocol == "snell"
	) then
		return true
	end
	if node.type == "tuic" then
		return true
	end
	if node.type == "anytls" then
		return true
	end
	return false
end

local function buildMihomoSubscribeYaml(nodes, group_name)
	-- 如果不使用 Mihomo 模式，返回 nil
	if not should_use_mihomo_mode() then
		return nil, 0
	end
	
	local proxies = {}
	local names = {}

	for _, node in ipairs(nodes) do
		local proxy = to_mihomo_proxy(node)
		if proxy then
			proxies[#proxies + 1] = proxy
			names[#names + 1] = proxy.name
		end
	end

	if #proxies == 0 then
		return nil, 0
	end

	local doc = {
		mode = "rule",
		["log-level"] = "silent",
		proxies = proxies,
		["proxy-groups"] = {
			{
				name = group_name,
				type = "select",
				proxies = names
			}
		},
		rules = { "MATCH," .. group_name }
	}

	local ok_lyaml, lyaml = pcall(require, "lyaml")
	if ok_lyaml then
		local ok_dump, dumped = pcall(lyaml.dump, { doc })
		if ok_dump and dumped then
			return dumped, #proxies
		end
	end

	return nil, 0
end

local function processLocalClashSubscription(path, alias)
	local result = {
		type = "clash",
		server = "127.0.0.1",
		server_port = "0",
		clash_path = path,
		clash_user_agent = user_agent,
		raw_alias = alias,
		alias = alias
	}

	local saved_alias = result.alias
	result.alias = nil
	result.hashkey = md5(jsonStringify(result) .. "_" .. (saved_alias or ""))
	result.alias = saved_alias
	return result
end
-- 处理数据
local function processData(szType, content, cfgid)
	local result = {type = szType, kcp_param = '--nocomp'}
	-- 检查JSON的格式如不完整丢弃
	if not (szType == "sip008" or szType == "ssd") then
		if not isCompleteJSON(content) then
			return nil
		end
	end

	if szType == "hysteria2" or szType == "hy2" then
		local url = URL.parse("http://" .. content)
		local params = url.query

		if not has_xray and not has_mihomo then
			return nil
		end

		result.type = "v2ray"
		result.v2ray_protocol = "hysteria2"
		if params.fm and params.fm ~= "" then
			result.enable_finalmask = "1"
			result.finalmask = base64Encode(params.fm)
		end
		if (params.security and params.security:lower() == "tls")
				or (params.sni and params.sni ~= "")
				or (params.alpn and params.alpn ~= "")
				or (params.pcs or params.vcn) then
			result.tls = "1"
			if params.sni then
				result.tls_host = params.sni
			end
			if params.alpn and params.alpn ~= "" then
				local alpn = {}
				for v in params.alpn:gmatch("[^,;|%s]+") do
					table.insert(alpn, v)
				end
				if #alpn > 0 then
					result.tls_alpn = table.concat(alpn, ",")
				end
			end
			if params.pcs then
				result.tls_CertSha = params.pcs
			end
			if params.vcn then
				result.tls_CertByName = params.vcn
			end
		end

		local raw_alias = url.fragment and UrlDecode(url.fragment) or nil
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）
		result.server = normalize_host(url.host)
		result.server_port = url.port or 443
		result.hy2_auth = url.user

		if params.mport then
			result.flag_port_hopping = "1"
			result.port_range = params.mport
		end
		result.uplink_capacity = tonumber((params.upmbps or ""):match("^(%d+)")) or nil
		result.downlink_capacity = tonumber((params.downmbps or ""):match("^(%d+)")) or nil
		if params.obfs and params.obfs ~= "none" then
			result.flag_obfs = "1"
			result.obfs_type = params.obfs
			result.salamander = params["obfs-password"] or params["obfs_password"]
		end
		if params.allowInsecure or params.insecure then
			local insecure = params.allowInsecure or params.insecure
			if insecure == true or insecure == "1" or insecure == "true" then
				result.insecure = "1"
			end
		end
		if params.tfo then
			-- 处理 fast open 参数
			result.fast_open = params.tfo
		end
	elseif szType == "snell" then
		if not has_mihomo then
			log("跳过 Snell 节点：本地未安装 mihomo。")
			return nil
		end

		local url = URL.parse("http://" .. content)
		local params = url.query or {}
		local raw_alias = url.fragment and UrlDecode(url.fragment) or nil
		local psk = url.user and UrlDecode(url.user) or first_nonempty(params, {"psk", "password"})

		result.type = "v2ray"
		result.v2ray_protocol = "snell"
		result.raw_alias = raw_alias
		result.alias = raw_alias
		result.server = normalize_host(url.host)
		result.server_port = url.port
		result.snell_psk = psk
		result.snell_version = first_nonempty(params, {"version", "v"}) or "4"
		result.snell_obfs = first_nonempty(params, {"obfs", "obfs-mode", "obfs_mode"})
		result.snell_obfs_host = first_nonempty(params, {"obfs-host", "obfs_host", "host"})
		if not result.snell_psk or result.snell_psk == "" then
			result.server = nil
		end
	elseif szType == 'ssr' then
		-- 去掉前后空白和#注释
		local link = trim(content:gsub("#.*$", ""))
		local dat = split(link, "/%?")
		local host, port, rest
		local hostinfo = dat[1] or ''
		if hostinfo:find("^%[.*%]:") then
			host, port, rest = hostinfo:match("^%[(.*)%]:(%d+):(.*)$")
		else
			host, port, rest = hostinfo:match("^(.-):(%d+):(.*)$")
		end

		result.type = 'ssr'
		local ssr_parts = split(rest or '', ':')
		result.server = normalize_host(host or '')
		result.server_port = port or ''
		result.protocol = ssr_parts[1] or ''
		result.encrypt_method = ssr_parts[2] or ''
		result.obfs = ssr_parts[3] or ''
		result.password = base64Decode(ssr_parts[4] or '')

		local params = {}
		if dat[2] and dat[2] ~= '' then
            for _, v in pairs(split(dat[2], '&')) do
                local t = split(v, '=')
                if t[1] and t[2] then
                    params[t[1]] = t[2]
                end
            end
		end

		result.obfs_param = base64Decode(params.obfsparam or '')
		result.protocol_param = base64Decode(params.protoparam or '')

		if params.tfo then
			-- 处理 fast open 参数
			result.fast_open = params.tfo
		end

		local group = base64Decode(params.group or '')
		local remarks = base64Decode(params.remarks or '')

		-- 拼接 alias
		local raw_alias = ""
		if group ~= "" then
			raw_alias = "[" .. group .. "] "
		end
		raw_alias = raw_alias .. remarks
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）
	elseif szType == "vmess" then
		-- 去掉前后空白和注释
		local link = trim(content:gsub("#.*$", ""))

		-- Base64 解码
		local decoded = base64Decode(link)
		if not decoded or decoded == "" then
			return nil
		end

		-- 解析 JSON
		local ok, info = pcall(jsonParse, decoded)
		if not ok or type(info) ~= "table" then
			return nil
		end

		-- 基本信息
		result.type = 'v2ray'
		result.v2ray_protocol = 'vmess'
		result.server = info.add
		result.server_port = info.port
		result.alter_id = info.aid
		result.vmess_id = info.id
		result.raw_alias = info.ps   -- 新增
		result.alias = info.ps       -- 临时赋值（后面会被覆盖）

		-- 调整传输协议
		if info.net == "tcp" then
			info.net = "raw"
		end
		if info.net == "splithttp" then
			info.net = "xhttp"
		end
		result.transport = info.net

		-- result.mux = 1
		-- result.concurrency = 8
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
		end
		if info.net == 'httpupgrade' then
			result.httpupgrade_host = info.host
			result.httpupgrade_path = info.path
		end
		if info.net == 'xhttp' or info.net == 'splithttp' then
			result.xhttp_mode = info.mode
			result.xhttp_host = info.host
			result.xhttp_path = info.path
			-- 检查 extra 参数是否存在且非空
			if info.extra and info.extra ~= "" then
				result.enable_xhttp_extra = "1"
				result.xhttp_extra = base64Encode(info.extra)
			end
			-- 尝试解析 JSON 数据
			local success, Data = pcall(jsonParse, info.extra or "")
			if success and type(Data) == "table" then
				local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
					or (Data.downloadSettings and Data.downloadSettings.address)
				result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "")
			else
				-- 如果解析失败，清空下载地址
				result.download_address = nil
			end
		end
		if info.net == 'h2' then
			result.h2_host = info.host
			result.h2_path = info.path
		end
		if info.net == 'raw' or info.net == 'tcp' then
			result.tcp_guise = info.type or "none"
			if result.tcp_guise == "http" then
				result.http_host = info.host
				result.http_path = info.path
			end
		end
		if info.net == 'kcp' then
			result.kcp_guise = info.type or "none"
			if info.type and info.type == "dns" then
				result.kcp_guise = info.host or ""
			end
			result.seed = params.seed
		end
		if info.net == 'grpc' then
			if info.path then
				result.serviceName = info.path
			elseif info.serviceName then
				result.serviceName = info.serviceName
			end
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.security
		end
		if info.security then
			result.security = info.security
		end
		if info.fm and info.fm ~= "" then
			info.fm = UrlDecode(info.fm)
			result.enable_finalmask = "1"
			result.finalmask = base64Encode(info.fm)
		end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.fingerprint = info.fp
			if info.alpn and info.alpn ~= "" then
				local alpn = {}
				for v in info.alpn:gmatch("[^,]+") do
					table.insert(alpn, v)
				end
				if #alpn > 0 then
					result.tls_alpn = table.concat(alpn, ",")  -- 确保为字符串
				end
			end
			if info.sni and info.sni ~= "" then
				result.tls_host = info.sni
			elseif info.host and info.host ~= "" then
				result.tls_host = info.host
			end
			if info.ech and info.ech ~= "" then
				result.enable_ech = "1"
				result.ech_config = info.ech
			end
			if info.pcs and info.pcs ~= "" then
				result.tls_CertSha = info.pcs
			end
			if info.vcn and info.vcn ~= "" then
				result.tls_CertByName = info.vcn
			end
			-- 兼容 allowInsecure / allowlnsecure / skip-cert-verify
			if info.allowInsecure or info.allowlnsecure or info.insecure or info["skip-cert-verify"] then
				local insecure = info.allowInsecure or info.allowlnsecure or info.insecure or info["skip-cert-verify"]
				if insecure == true or insecure == "1" or insecure == "true" then
					result.insecure = "1"
				end
			end
		else
			result.tls = "0"
		end
	elseif szType == "ss" then
		local idx_sp = content:find("#") or 0
		local alias = ""
		if idx_sp > 0 then
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1):gsub("/%?", "?")
		end
		local raw_alias = UrlDecode(alias)
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）

		-- 拆 base64 主体和 ? 参数部分
		local info = content
		local find_index, query = info:match("^([^?]+)%??(.*)$")
		--log("SS 节点格式:", find_index)
		local params = {}
		if query and query ~= "" then
			for _, v in ipairs(split(query, '&')) do
				local t = split(v, '=')
				if #t >= 2 then
					params[t[1]] = UrlDecode(t[2])
				end
			end
		end

		if params.tfo and params.tfo ~= "" then
			-- 处理 fast open 参数
			result.fast_open = params.tfo
		end

		local selected_ss_backend = preferred_ss_backend()
		local xray_ss_mode = (selected_ss_backend == "v2ray")

		-- 如果最终无可用核心，跳过该订阅
		if selected_ss_backend == nil then
			return nil
		end

		if xray_ss_mode then
			local url = URL.parse("http://" .. info)
			local params = url.query

			result.type = "v2ray"
			result.v2ray_protocol = "shadowsocks"
			result.server = normalize_host(url.host)
			result.server_port = url.port

			-- 判断 @ 前部分是否为 Base64
			local is_base64 = base64Decode(UrlDecode(url.user))
			if is_base64:find(":") then
        		-- 新格式：method:password
        		result.encrypt_method_ss, result.password = is_base64:match("^(.-):(.*)$")
			else
				-- 旧格式：UUID 直接作为密码
				result.password = url.user
				result.encrypt_method_ss = params.encryption or "none"
			end

			if params.udp then
				-- 处理 udp 参数
				result.uot = params.udp
			end

			result.transport = params.type or "raw"
			if result.transport == "tcp" then
				result.transport = "raw"
			end
			if result.transport == "splithttp" then
				result.transport = "xhttp"
			end
			result.tls = (params.security == "tls" or params.security == "xtls") and "1" or "0"
			if params.alpn and params.alpn ~= "" then
				local alpn = {}
				for v in params.alpn:gmatch("[^,;|%s]+") do
					table.insert(alpn, v)
				end
				if #alpn > 0 then
					result.tls_alpn = table.concat(alpn, ",")  -- 确保为字符串
				end
			end
			if params.pcs and params.pcs ~= "" then
				result.tls_CertSha = params.pcs
			end
			if params.vcn and params.vcn ~= "" then
				result.tls_CertByName = params.vcn
			end
			result.tls_host = params.sni
			result.tls_flow = (params.security == "tls" or params.security == "reality") and params.flow or nil
			result.fingerprint = params.fp
			result.reality = (params.security == "reality") and "1" or "0"
			result.reality_publickey = params.pbk and UrlDecode(params.pbk) or nil
			result.reality_shortid = params.sid
			result.reality_spiderx = params.spx and UrlDecode(params.spx) or nil
			-- 检查 ech 参数是否存在且非空
			if params.ech and params.ech ~= "" then
				result.enable_ech = "1"
				result.ech_config = params.ech
			end
			-- 检查 finalmaskg 参数是否存在且非空
			if params.fm and params.fm ~= "" then
				result.enable_finalmask = "1"
				result.finalmask = base64Encode(params.fm)
			end
			-- 检查 pqv 参数是否存在且非空
			if params.pqv and params.pqv ~= "" then
				result.enable_mldsa65verify = "1"
				result.reality_mldsa65verify = params.pqv
			end
			if params.allowInsecure or params.insecure then
				local insecure = params.allowInsecure or params.insecure
				if insecure == true or insecure == "1" or insecure == "true" then
					result.insecure = "1"
				end
			end
			if result.transport == "ws" then
				result.ws_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
				result.ws_path = params.path and UrlDecode(params.path) or "/"
			elseif result.transport == "httpupgrade" then
				result.httpupgrade_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
				result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"
			elseif result.transport == "xhttp" or result.transport == "splithttp" then
				result.xhttp_mode = params.mode or "auto"
				result.xhttp_host = params.host and UrlDecode(params.host) or nil
				result.xhttp_path = params.path and UrlDecode(params.path) or "/"
				-- 检查 extra 参数是否存在且非空
				if params.extra and params.extra ~= "" then
					result.enable_xhttp_extra = "1"
					result.xhttp_extra = base64Encode(params.extra)
				end
				-- 尝试解析 JSON 数据
				local success, Data = pcall(jsonParse, params.extra or "")
				if success and type(Data) == "table" then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
						or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "")
				else
					-- 如果解析失败，清空下载地址
					result.download_address = nil
				end
			-- make it compatible with bullshit, "h2" transport is non-existent at all
			elseif result.transport == "http" or result.transport == "h2" then
				result.transport = "h2"
				result.h2_host = params.host and UrlDecode(params.host) or nil
				result.h2_path = params.path and UrlDecode(params.path) or nil
			elseif result.transport == "kcp" then
				result.kcp_guise = params.headerType or "none"
				if params.headerType and params.headerType == "dns" then
					result.kcp_domain = params.host or ""
				end
				result.seed = params.seed
			elseif result.transport == "quic" then
				result.quic_guise = params.headerType or "none"
				result.quic_security = params.quicSecurity or "none"
				result.quic_key = params.key
			elseif result.transport == "grpc" then
				result.serviceName = params.serviceName
				result.grpc_mode = params.mode or "gun"
			elseif result.transport == "tcp" or result.transport == "raw" then
				result.tcp_guise = params.headerType or "none"
				if result.tcp_guise == "http" then
					result.tcp_host = params.host and UrlDecode(params.host) or nil
					result.tcp_path = params.path and UrlDecode(params.path) or nil
				end
			end
		else
			local is_old_format = find_index:find("@") and not find_index:find("://.*@")
			local old_base64, host_port, userinfo, server, port, method, password

			if is_old_format then
				-- 旧格式：base64(method:pass)@host:port
				old_base64, host_port = find_index:match("^([^@]+)@(.-)$")
				log("SS 节点旧格式解析:", old_base64)
				if not old_base64 or not host_port then
					log("SS 节点旧格式解析失败:", find_index)
					return nil
				end
				local decoded = base64Decode(UrlDecode(old_base64))
				if not decoded then
					log("SS base64 解码失败（旧格式）:", old_base64)
					return nil
				end
				userinfo = decoded
			else
				-- 新格式：base64(method:pass@host:port)
				local decoded = base64Decode(UrlDecode(find_index))
				if not decoded then
					log("SS base64 解码失败（新格式）:", find_index)
					return nil
				end
				userinfo, host_port = decoded:match("^(.-)@(.-)$")
				if not userinfo or not host_port then
					log("SS 解码内容缺失 @ 分隔:", decoded)
					return nil
				end
			end

			-- 解析加密方式和密码（允许密码包含冒号）
			local meth_pass = userinfo:find(":")
			if not meth_pass then
				log("SS 用户信息格式错误:", userinfo)
				return nil
			end
			method = userinfo:sub(1, meth_pass - 1)
			password = userinfo:sub(meth_pass + 1)

			-- 判断密码是否经过url编码
			local function isURLEncodedPassword(pwd)
				if not pwd:find("%%[0-9A-Fa-f][0-9A-Fa-f]") then
					return false
				end
				local ok, decoded = pcall(UrlDecode, pwd)
				return ok and urlEncode(decoded) == pwd
			end

			local decoded = UrlDecode(password)
			if isURLEncodedPassword(password) and decoded then
				password = decoded
			end

			-- 解析服务器地址和端口（兼容 IPv6）
			if host_port:find("^%[.*%]:%d+$") then
				server, port = host_port:match("^%[(.*)%]:(%d+)$")
			else
				server, port = host_port:match("^(.-):(%d+)$")
			end
			if not server or not port then
				log("SS 节点服务器信息格式错误:", host_port)
				return nil
			end

			-- 填充 result
			result.type = selected_ss_backend
			result.encrypt_method_ss = method
			result.password = password
			result.server = server
			result.server_port = port

			-- 插件处理
			if params.plugin then
				local plugin_info = UrlDecode(params.plugin)
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
					result.plugin_opts = ""
				end
				-- 部分机场下发的插件名为 simple-obfs，这里应该改为 obfs-local
				if result.plugin == "simple-obfs" then
					result.plugin = "obfs-local"
				end
				-- 如果插件不为 none，确保 enable_plugin 为 1
				if result.plugin ~= "none" and result.plugin ~= "" then
					result.enable_plugin = 1
				end
			else
				if params["shadow-tls"] then
					-- 特别处理 shadow-tls 作为插件
					-- log("原始 shadow-tls 参数:", params["shadow-tls"])
					local decoded_tls = base64Decode(UrlDecode(params["shadow-tls"]))
					--log("SS 节点 shadow-tls 解码后:", decoded_tls or "nil")
					if decoded_tls then
						local ok, st = pcall(jsonParse, decoded_tls)
						if ok and st then
							result.plugin = "shadow-tls"
							result.enable_plugin = 1
							local version_flag = ""
							if st.version and tonumber(st.version) then
								version_flag = string.format("v%s=1;", st.version)
							end
					
							-- 合成 plugin_opts 格式：v%s=1;host=xxx;password=xxx
							result.plugin_opts = string.format("%shost=%s;passwd=%s",
								version_flag,
								st.host or "",
								st.password or "")
						else
							log("shadow-tls JSON 解析失败")
						end
					end
				end
			end

			-- 检查加密方法是否受支持
			if not checkTabValue(encrypt_methods_ss)[method] then
				-- 1202 年了还不支持 SS AEAD 的屑机场
				-- log("不支持的SS加密方法:", method)
				result.server = nil
			end
		end
	elseif szType == "sip008" then
		local selected_ss_backend = preferred_ss_backend()
		if not selected_ss_backend then
			return nil
		end
		result.type = selected_ss_backend
		if selected_ss_backend == "v2ray" then
			result.v2ray_protocol = "shadowsocks"
		end
		result.server = content.server
		result.server_port = content.server_port
		result.password = content.password
		result.encrypt_method_ss = content.method
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_opts
		result.raw_alias = content.remarks   -- 新增
		result.alias = content.remarks       -- 临时赋值（后面会被覆盖）
		if not checkTabValue(encrypt_methods_ss)[content.method] then
			result.server = nil
		end
	elseif szType == "ssd" then
		local selected_ss_backend = preferred_ss_backend()
		if not selected_ss_backend then
			return nil
		end
		result.type = selected_ss_backend
		if selected_ss_backend == "v2ray" then
			result.v2ray_protocol = "shadowsocks"
		end
		result.server = content.server
		result.server_port = content.port
		result.password = content.password
		result.encrypt_method_ss = content.method
		result.plugin_opts = content.plugin_options
		local raw_alias = "[" .. content.airport .. "] " .. content.remarks
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）
		if content.plugin == "simple-obfs" then
			result.plugin = "obfs-local"
		else
			result.plugin = content.plugin
		end
		if not checkTabValue(encrypt_methods_ss)[content.encryption] then
			result.server = nil
		end
	elseif szType == "trojan" then
		-- 提取别名（如果存在）
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		local raw_alias = UrlDecode(alias)
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）

		-- 分离和提取 password		
		local Info = content
		local params = {}
		if Info:find("@") then
			local contents = split(Info, "@")
			result.password = UrlDecode(contents[1])
			local port = "443"
			Info = (contents[2] or ""):gsub("/%?", "?")

			-- 分离主机和 query 参数（key=value&key2=value2）
			local query = split(Info, "%?")
			local host_port = query[1]
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				if #t > 1 then
					params[string.lower(t[1])] = UrlDecode(t[2])
				end
			end

			-- 提取服务器地址和端口
			result.server, result.server_port = parse_host_port(host_port, "443")

			-- 默认设置
			-- 按照官方的建议 默认验证ssl证书
			result.insecure = "0"
			result.tls = "1"

			-- 处理参数
			if params.alpn and params.alpn ~= "" then
				-- 处理 alpn 参数
				local alpn = {}
				for v in params.alpn:gmatch("[^,;|%s]+") do
					table.insert(alpn, v)
				end
				if #alpn > 0 then
					result.tls_alpn = table.concat(alpn, ",")  -- 确保为字符串
				end
			end

			do
				local tls_host = first_nonempty(params, {"peer", "sni", "host"})
				if tls_host then
					-- 未指定 peer/sni 时，兼容使用 host 作为 TLS Host
					result.tls_host = tls_host
				end
			end
			-- 处理 insecure 参数
			do
				local insecure = first_nonempty(params, {
					"allowInsecure",
					"allowinsecure",
					"allow_insecure",
					"insecure",
					"skip-cert-verify"
				})
				if is_true_value(insecure) then
					result.insecure = "1"
				end
			end
			if params.tfo then
				-- 处理 fast open 参数
				result.fast_open = params.tfo
			end
		else
			result.server_port = port
		end

		-- 自动决定模式（true=Xray, false=普通 Trojan）
		if not has_xray and not has_mihomo then
			return nil
		end

		result.type = "v2ray"
		result.v2ray_protocol = "trojan"
		if params.fp then
			-- 处理 fingerprint 参数
			result.fingerprint = params.fp
		end
		-- 处理 ech 参数
		if params.ech and params.ech ~= "" then
			result.enable_ech = "1"
			result.ech_config = params.ech
		end
		-- 检查 finalmaskg 参数是否存在且非空
		if params.fm and params.fm ~= "" then
			result.enable_finalmask = "1"
			result.finalmask = base64Encode(params.fm)
		end
		-- 处理传输协议
		result.transport = params.type or "raw" -- 默认传输协议为 raw
		if result.transport == "tcp" then
			result.transport = "raw"
		end
		if result.transport == "splithttp" then
			result.transport = "xhttp"
		end
		if params.pcs and params.pcs ~= "" then
			result.tls_CertSha = params.pcs
		end
		if params.vcn and params.vcn ~= "" then
			result.tls_CertByName = params.vcn
		end
		if result.transport == "ws" then
			result.ws_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.ws_path = params.path and UrlDecode(params.path) or "/"
		elseif result.transport == "httpupgrade" then
			result.httpupgrade_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"
		elseif result.transport == "xhttp" or result.transport == "splithttp" then
			result.xhttp_mode = params.mode or "auto"
			result.xhttp_host = params.host and UrlDecode(params.host) or nil
			result.xhttp_path = params.path and UrlDecode(params.path) or "/"
			-- 检查 extra 参数是否存在且非空
			if params.extra and params.extra ~= "" then
				result.enable_xhttp_extra = "1"
				result.xhttp_extra = base64Encode(params.extra)
			end
			-- 尝试解析 JSON 数据
			local success, Data = pcall(jsonParse, params.extra or "")
			if success and type(Data) == "table" then
				local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
					or (Data.downloadSettings and Data.downloadSettings.address)
				result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "")
			else
				-- 如果解析失败，清空下载地址
				result.download_address = nil
			end
		elseif result.transport == "http" or result.transport == "h2" then
			result.transport = "h2"
			result.h2_host = params.host and UrlDecode(params.host) or nil
			result.h2_path = params.path and UrlDecode(params.path) or nil
		elseif result.transport == "kcp" then
			result.kcp_guise = params.headerType or "none"
			if params.headerType and params.headerType == "dns" then
				result.kcp_domain = params.host or ""
			end
			result.seed = params.seed
		elseif result.transport == "quic" then
			result.quic_guise = params.headerType or "none"
			result.quic_security = params.quicSecurity or "none"
			result.quic_key = params.key
		elseif result.transport == "grpc" then
			result.serviceName = params.serviceName
			result.grpc_mode = params.mode or "gun"
		elseif result.transport == "tcp" or result.transport == "raw" then
			result.tcp_guise = params.headerType and params.headerType ~= "" and params.headerType or "none"
			if result.tcp_guise == "http" then
				result.tcp_host = params.host and UrlDecode(params.host) or nil
				result.tcp_path = params.path and UrlDecode(params.path) or nil
			end
		end
	elseif szType == "vless" then
		local url = URL.parse("http://" .. content)
		local params = url.query

		local raw_alias = url.fragment and UrlDecode(url.fragment) or nil
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）
		result.type = "v2ray"
		result.v2ray_protocol = "vless"
		result.server = normalize_host(url.host)
		result.server_port = url.port
		result.vmess_id = url.user
		result.vless_encryption = params.encryption or "none"

		-- 处理传输类型
		result.transport = params.type or "raw"
		if result.transport == "tcp" then
			result.transport = "raw"
		elseif result.transport == "splithttp" then
			result.transport = "xhttp"
		elseif result.transport == "http" then
			result.transport = "h2"
		end

		-- TLS / Reality 标志
		local security = params.security or ""
		result.tls = (security == "tls" or security == "xtls") and "1" or "0"
		result.reality = (security == "reality") and "1" or "0"

		-- 统一 TLS / Reality 公共字段
		result.tls_host = params.sni
		result.fingerprint = params.fp
		result.tls_flow = params.flow or nil

		-- 处理 alpn 列表
		if params.alpn and params.alpn ~= "" then
			local alpn = {}
			for v in params.alpn:gmatch("[^,;|%s]+") do
				table.insert(alpn, v)
			end
			if #alpn > 0 then
				result.tls_alpn = table.concat(alpn, ",")  -- 确保为字符串
			end
		end

		-- 处理 insecure 参数
		if params.allowInsecure or params.insecure then
			local insecure = params.allowInsecure or params.insecure
			if insecure == true or insecure == "1" or insecure == "true" then
				result.insecure = "1"
			end
		end

		-- ECH 参数（TLS 才有）
		if security == "tls" and params.ech and params.ech ~= "" then
			result.enable_ech = "1"
			result.ech_config = params.ech
		end

		-- 处理 finalmask 参数
		if params.fm and params.fm ~= "" then
			result.enable_finalmask = "1"
			result.finalmask = base64Encode(params.fm)
		end

		-- 处理 pinsha256 参数
		if params.pcs and params.pcs ~= "" then
			result.tls_CertSha = params.pcs
		end

		-- 处理 Leaf Certificate Name 参数
		if params.vcn and params.vcn ~= "" then
			result.tls_CertByName = params.vcn
		end

		-- Reality 参数
		if security == "reality" then
			result.reality_publickey = params.pbk and UrlDecode(params.pbk) or nil
			result.reality_shortid = params.sid
			result.reality_spiderx = params.spx and UrlDecode(params.spx) or nil

			-- PQV 验证参数
			if params.pqv and params.pqv ~= "" then
				result.enable_mldsa65verify = "1"
				result.reality_mldsa65verify = params.pqv
			end
		end

		-- 各种传输类型
		if result.transport == "ws" then
			result.ws_host = (result.tls ~= "1" and result.reality ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.ws_path = params.path and UrlDecode(params.path) or "/"
		elseif result.transport == "httpupgrade" then
			result.httpupgrade_host = (result.tls ~= "1" and result.reality ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"
		elseif result.transport == "xhttp" then
			result.xhttp_mode = params.mode or "auto"
			result.xhttp_host = params.host and UrlDecode(params.host) or nil
			result.xhttp_path = params.path and UrlDecode(params.path) or "/"
			if params.tfo then
				-- 处理 fast open 参数
				result.fast_open = params.tfo
			end
			if params.extra and params.extra ~= "" then
				result.enable_xhttp_extra = "1"
				result.xhttp_extra = base64Encode(params.extra)
			end
			local success, Data = pcall(jsonParse, params.extra or "")
			if success and type(Data) == "table" then
				local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
					or (Data.downloadSettings and Data.downloadSettings.address)
				result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "")
			else
				result.download_address = nil
			end
		elseif result.transport == "h2" then
			result.h2_host = params.host and UrlDecode(params.host) or nil
			result.h2_path = params.path and UrlDecode(params.path) or nil
		elseif result.transport == "kcp" then
			result.kcp_guise = params.headerType or "none"
			if params.headerType and params.headerType == "dns" then
				result.kcp_domain = params.host or ""
			end
			result.seed = params.seed
		elseif result.transport == "quic" then
			result.quic_guise = params.headerType or "none"
			result.quic_security = params.quicSecurity or "none"
			result.quic_key = params.key
		elseif result.transport == "grpc" then
			result.serviceName = params.serviceName
			result.grpc_mode = params.mode or "gun"
		elseif result.transport == "raw" then
			result.tcp_guise = params.headerType or "none"
			if result.tcp_guise == "http" then
				result.tcp_host = params.host and UrlDecode(params.host) or nil
				result.tcp_path = params.path and UrlDecode(params.path) or nil
			end
		end
	elseif szType == "tuic" then
		if not tuic_type then
			log("跳过 TUIC 节点：本地未安装 mihomo。")
			return nil
		end

		-- 提取别名（如果存在）
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		local raw_alias = UrlDecode(alias)
		result.raw_alias = raw_alias   -- 新增
		result.alias = raw_alias       -- 临时赋值（后面会被覆盖）

		-- 分离和提取 uuid 和 password
		local Info = content
		if Info:find("@") then
			local contents = split(Info, "@")
			local userinfo_raw = UrlDecode(contents[1] or "") -- 如有Url编码进行解码
			if userinfo_raw:find(":") then
				local userinfo = split(userinfo_raw, ":")
				result.tuic_uuid = userinfo[1]
				result.tuic_passwd = userinfo[2]
			end
			Info = (contents[2] or ""):gsub("/%?", "?")
		end

		-- 分离主机和 query 参数（key=value&key2=value2）
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end

		-- 提取服务器地址和端口
		result.server, result.server_port = parse_host_port(host_port, "443")

		result.type = tuic_type
		result.tuic_ip = params.ip or ""
		result.udp_relay_mode = params.udp_relay_mode or "native"
		result.congestion_control = params.congestion_control or "cubic"
		result.heartbeat = params.heartbeat or "3"
		result.timeout = params.timeout or "8"
		result.gc_interval = params.gc_interval or "3"
		result.gc_lifetime = params.gc_lifetime or "15"
		result.send_window = params.send_window or "20971520"
		result.receive_window = params.receive_window or "10485760"
		result.tuic_max_package_size = params.max_packet_size or "1500"

		-- alpn 支持逗号或分号分隔
		if params.alpn and params.alpn ~= "" then
			local alpn = {}
			for v in params.alpn:gmatch("[^,;|%s]+") do
				table.insert(alpn, v)
			end
			if #alpn > 0 then
				result.tls_alpn = table.concat(alpn, ",")  -- 确保为字符串
			end
		end

		-- 处理 disable_sni 参数
		if params.disable_sni then
			if params.disable_sni == "1" or params.disable_sni == "0" then
				result.disable_sni = params.disable_sni
			else
				result.disable_sni = string.lower(params.disable_sni) == "true" and "1" or "0"
			end
		end

		-- 处理 zero_rtt_handshake 参数
		if params.zero_rtt_handshake then
			if params.zero_rtt_handshake == "1" or params.zero_rtt_handshake == "0" then
				result.zero_rtt_handshake = params.zero_rtt_handshake
			else
				result.zero_rtt_handshake = string.lower(params.zero_rtt_handshake) == "true" and "1" or "0"
			end
		end

		-- 处理 dual_stack 参数
		if params.dual_stack then
			if params.dual_stack == "1" or params.dual_stack == "0" then
				result.dual_stack = params.dual_stack
			else
				result.dual_stack = string.lower(params.dual_stack) == "true" and "1" or "0"
			end
			-- 处理 ipstack_prefer 参数
			if params.ipstack_prefer and params.ipstack_prefer ~= "" then
				result.ipstack_prefer = params.ipstack_prefer
			end
		end

		-- 兼容 allowInsecure / allowlnsecure / insecure
		if params.allowInsecure or params.allowlnsecure or params.insecure then
			local insecure = params.allowInsecure or params.allowlnsecure or params.insecure
			if insecure == true or insecure == "1" or insecure == "true" then
				result.insecure = "1"
			end
		end
	end

	if not result.type or result.type == "" or result.type == "0" then
		return nil
	end

	if not result.alias then
		if result.server and result.server_port then
			result.alias = result.server .. ':' .. result.server_port
		else
			result.alias = "NULL"
		end
		result.raw_alias = result.alias
	end
	-- alias 不参与 hashkey 计算
	local alias = result.alias
	result.alias = nil
	local switch_enable = result.switch_enable
	result.switch_enable = nil
	result.hashkey = md5(jsonStringify(result) .. "_" .. (alias or ""))
	result.alias = alias
	result.switch_enable = switch_enable
	return result
end

-- 计算、储存和读取 md5 值
-- 计算 md5 值
local function md5_string(data)
	-- 生成临时文件名
	local tmp = "/tmp/md5_tmp_" .. os.time() .. "_" .. math.random(1000,9999) -- os.time 保证每秒唯一，但不足以避免全部冲突；math.random(1000,9999) 增加文件名唯一性，避免并发时冲突
	nixio.fs.writefile(tmp, data) -- 写入临时文件
	-- 执行 md5sum 命令
	local md5 = luci.sys.exec(string.format('md5sum "%s" 2>/dev/null | cut -d " " -f1', tmp)):gsub("%s+", "")
	nixio.fs.remove(tmp) -- 删除临时文件
	return md5
end

-- 返回临时文件路径，用来存储订阅的 MD5 值，以便判断订阅内容是否发生变化。
local function get_md5_path(groupHash)
	return "/tmp/sub_md5_" .. groupHash
end

-- 读取上次订阅时记录的 MD5 值，以便和当前内容的 MD5 进行对比，从而判断是否需要更新节点列表。
local function read_old_md5(groupHash)
	local path = get_md5_path(groupHash)
	if nixio.fs.access(path) then
		return trim(nixio.fs.readfile(path) or "")
	end
	return ""
end

-- 将订阅分组最新内容的 MD5 值保存到对应的临时文件中，以便下次更新时进行对比。
local function write_new_md5(groupHash, md5)
	nixio.fs.writefile(get_md5_path(groupHash), md5)
end

-- curl
local function curl(url, user_agent)
	-- 清理 URL 中的隐藏字符和前后空白
	url = url:gsub("%s+$", ""):gsub("^%s+", ""):gsub("%z", ""):gsub("[\r\n]", "")
	-- 处理 user_agent 参数
	local ua_opt = ""
	if user_agent and user_agent ~= "" then
		-- 转义双引号，防止破坏 -A 参数
		local safe_ua = user_agent:gsub("[\r\n]", ""):gsub('[\\"`$]', '\\%0')  -- 安全转义
		ua_opt = '-A "' .. safe_ua .. '"'
	end
	-- 安全转义 URL：用单引号包裹，并转义内部的单引号
	local safe_url = "'" .. url:gsub("'", "'\\''") .. "'"
	local cmd = string.format(
		'curl -sSL --http1.1 --connect-timeout 20 --max-time 30 --retry 3 -H "Accept-Encoding: identity" %s --insecure --location %s',
		ua_opt,
		safe_url
	)
	-- 执行命令并获取输出
	local stdout = luci.sys.exec(cmd)
	stdout = trim(stdout)  -- 确保 trim 函数存在
	local md5 = md5_string(stdout)  -- 确保 md5_string 函数存在
	return stdout, md5
end

local function build_convert_url(url)
	if sub_convert ~= "1" then
		return url, false
	end

	local tpl = trim(template_url or "")
	local endpoint = trim(convert_address or "")
	local exclude = trim(filter_words or "")
	if tpl == "" or endpoint == "" then
		return url, false
	end

	endpoint = endpoint:gsub("%s+$", ""):gsub("^%s+", ""):gsub("%z", ""):gsub("[\r\n]", "")
	local sep = endpoint:find("?", 1, true) and "&" or "?"
	local query = "target=clash"
		.. "&new_name=true"
		.. "&url=" .. urlEncodeRFC3986(url)
		.. "&config=" .. urlEncodeRFC3986(tpl)
		.. "&exclude=" .. urlEncodeRFC3986(exclude)
		.. "&emoji=false"
		.. "&list=false"
		.. "&sort=false"
		.. "&udp=true"
		.. "&scv=" .. (allow_insecure == "1" and "true" or "false")
		.. "&fdn=true"

	return endpoint .. sep .. query, true
end

local function filterClashYamlRaw(raw)
	if not raw or raw == "" then
		return raw, 0
	end

	local tmp = string.format("/tmp/ssrplus-subscribe-filter-%d-%d.yaml", nixio.getpid(), os.time())
	local ok = nixio.fs.writefile(tmp, raw)
	if not ok then
		return raw, 0
	end

	local removed = tonumber(trim(luci.sys.exec(string.format(
		"/usr/bin/lua /usr/share/shadowsocksr/clash_yaml.lua filter %s %s 2>/dev/null",
		shell_quote(tmp),
		shell_quote(filter_words)
	)))) or 0
	local filtered = nixio.fs.readfile(tmp) or raw
	nixio.fs.remove(tmp)
	return filtered, removed
end

local function collect_wan_interfaces()
	local ifaces = {}
	local seen = {}

	local function add_iface(value)
		value = trim(value or "")
		if value == "" or value == "nil" or value:sub(1, 1) == "@" then
			return
		end

		if value:find("%s") then
			for iface in value:gmatch("%S+") do
				add_iface(iface)
			end
			return
		end

		if not seen[value] then
			seen[value] = true
			ifaces[#ifaces + 1] = value
		end
	end

	local function add_iface_from_status(netif)
		local raw = trim(luci.sys.exec(string.format(
			"ubus -S call network.interface.%s status 2>/dev/null",
			netif
		)))
		if raw == "" then
			return
		end

		local status = jsonParse(raw)
		if type(status) ~= "table" then
			return
		end

		add_iface(status.l3_device)
		add_iface(status.device)
	end

	add_iface_from_status("wan")
	add_iface_from_status("wan6")

	if #ifaces == 0 then
		add_iface(ucic:get("network", "wan", "device"))
		add_iface(ucic:get("network", "wan", "ifname"))
		add_iface(ucic:get("network", "wan6", "device"))
		add_iface(ucic:get("network", "wan6", "ifname"))
	end

	if #ifaces == 0 then
		local route_output = luci.sys.exec("ip route show default 2>/dev/null")
		for iface in route_output:gmatch("dev%s+(%S+)") do
			add_iface(iface)
		end
	end

	if #ifaces == 0 then
		local route6_output = luci.sys.exec("ip -6 route show default 2>/dev/null")
		for iface in route6_output:gmatch("dev%s+(%S+)") do
			add_iface(iface)
		end
	end

	return ifaces
end

local function detect_subscribe_bypass_backend()
	if luci.sys.call("nft list chain inet ss_spec ss_spec_output >/dev/null 2>&1") == 0 then
		return "nftables"
	end

	local ipt_output = luci.sys.exec("iptables -t nat -S OUTPUT 2>/dev/null")
	if ipt_output:find("SS_SPEC_WAN_AC", 1, true) or ipt_output:find("SS_SPEC_ROUTER", 1, true) then
		return "iptables"
	end

	return nil
end

local function create_direct_subscribe_bypass()
	if proxy ~= "0" then
		return nil
	end

	local backend = detect_subscribe_bypass_backend()
	if not backend then
		log("直连订阅: 未检测到 SSR 路由器自身 OUTPUT 代理链，跳过临时绕过规则。")
		return nil
	end

	local wan_ifaces = collect_wan_interfaces()
	local targets = (#wan_ifaces > 0) and wan_ifaces or {false}
	local tag = string.format("SSR_SUB_BYPASS_%d", tonumber(nixio.getpid()) or os.time())
	local manager = {
		backend = backend,
		tag = tag,
		targets = targets,
		added = false
	}

	function manager:describe_target(target)
		if target then
			return target
		end
		return "all-output"
	end

	function manager:apply_iptables_rule(target)
		local cmd = {
			"iptables -t nat -I OUTPUT 1"
		}

		if target then
			cmd[#cmd + 1] = "-o " .. shell_quote(target)
		end

		cmd[#cmd + 1] = "-p tcp -m multiport --dports 80,443"
		cmd[#cmd + 1] = "-m comment --comment " .. shell_quote(self.tag)
		cmd[#cmd + 1] = "-j RETURN >/dev/null 2>&1"

		return luci.sys.call(table.concat(cmd, " ")) == 0
	end

	function manager:apply_nft_rule(target)
		local rule = {
			"nft insert rule inet ss_spec ss_spec_output"
		}

		if target then
			rule[#rule + 1] = "oifname " .. nft_string_literal(target)
		end

		rule[#rule + 1] = "meta l4proto tcp tcp dport { 80, 443 }"
		rule[#rule + 1] = "counter return"
		rule[#rule + 1] = "comment " .. nft_string_literal(self.tag)

		return luci.sys.call(table.concat(rule, " ") .. " >/dev/null 2>&1") == 0
	end

	function manager:apply()
		for index = #self.targets, 1, -1 do
			local target = self.targets[index]
			local ok

			if self.backend == "nftables" then
				ok = self:apply_nft_rule(target)
			else
				ok = self:apply_iptables_rule(target)
			end

			if ok then
				self.added = true
				log("直连订阅: 已添加临时绕过规则 -> " .. self.backend .. " / " .. self:describe_target(target))
			else
				log("直连订阅: 添加临时绕过规则失败 -> " .. self.backend .. " / " .. self:describe_target(target))
			end
		end

		if not self.added then
			log("直连订阅: 临时绕过规则未生效，订阅请求仍可能走代理。")
		end
	end

	function manager:cleanup_nft_rules()
		local output = luci.sys.exec("nft -a list chain inet ss_spec ss_spec_output 2>/dev/null")
		local pattern = 'comment "' .. escape_lua_pattern(self.tag) .. '".-# handle (%d+)'
		local handles = {}

		for handle in output:gmatch(pattern) do
			handles[#handles + 1] = handle
		end

		for _, handle in ipairs(handles) do
			luci.sys.call(string.format(
				"nft delete rule inet ss_spec ss_spec_output handle %s >/dev/null 2>&1",
				handle
			))
		end

		return #handles
	end

	function manager:cleanup_iptables_rules()
		local removed = 0

		for _, target in ipairs(self.targets) do
			local cmd = {
				"iptables -t nat -D OUTPUT"
			}

			if target then
				cmd[#cmd + 1] = "-o " .. shell_quote(target)
			end

			cmd[#cmd + 1] = "-p tcp -m multiport --dports 80,443"
			cmd[#cmd + 1] = "-m comment --comment " .. shell_quote(self.tag)
			cmd[#cmd + 1] = "-j RETURN >/dev/null 2>&1"

			if luci.sys.call(table.concat(cmd, " ")) == 0 then
				removed = removed + 1
			end
		end

		return removed
	end

	function manager:cleanup()
		if not self.added then
			return
		end

		local removed
		if self.backend == "nftables" then
			removed = self:cleanup_nft_rules()
		else
			removed = self:cleanup_iptables_rules()
		end

		log("直连订阅: 已清理临时绕过规则数量: " .. tostring(removed or 0))
		self.added = false
	end

	return manager
end

local function check_filer(result)
	-- 过滤的关键词列表
	local filter_word = split(filter_words, "/")
	-- 保留的关键词列表
	local check_save = false
	if save_words ~= nil and save_words ~= "" and save_words ~= "NULL" then
		check_save = true
	end
	local save_word = split(save_words, "/")

	-- 检查结果
	local filter_result = false
	local save_result = true

	-- 检查是否存在过滤关键词
	for i, v in pairs(filter_word) do
		if tostring(result.alias):find(v, nil, true) then
			filter_result = true
		end
	end

	-- 检查是否打开了保留关键词检查，并且进行过滤
	if check_save == true then
		for i, v in pairs(save_word) do
			if tostring(result.alias):find(v, nil, true) then
				save_result = false
			end
		end
	else
		save_result = false
	end

	-- 不等时返回
	if filter_result == true or save_result == true then
		return true
	else
		return false
	end
end

-- 加载订阅未变化的节点用于防止被误删
local function loadOldNodes(groupHash)
	local nodes = {}
	local count = 0
	cache[groupHash] = {}
	nodeResult[#nodeResult + 1] = nodes
	local index = #nodeResult

	ucic:foreach(name, uciType, function(s)
		if s.grouphashkey == groupHash and s.hashkey then
			local section = setmetatable({}, {__index = s})
			nodes[s.hashkey] = section
			cache[groupHash][s.hashkey] = section
			count = count + 1
		end
	end)

	return count
end

local function group_has_saved_nodes(groupHash)
	local found = false
	ucic:foreach(name, uciType, function(s)
		if s.grouphashkey == groupHash and s.hashkey then
			found = true
			return false
		end
	end)
	return found
end

local function get_section_ss_backend(section)
	if not section then
		return nil
	end
	if section.type == "ss" or section.type == "ss-libev" then
		return "ss"
	end
	if section.type == "ss-rust" then
		return "ss-rust"
	end
	if section.type == "v2ray" and section.v2ray_protocol == "shadowsocks" then
		return "v2ray"
	end
	return nil
end

local function group_needs_ss_backend_refresh(groupHash)
	local preferred = preferred_ss_backend()
	local has_ss_node = false
	local needs_refresh = false

	if not preferred then
		return false
	end

	ucic:foreach(name, uciType, function(s)
		if s.grouphashkey ~= groupHash then
			return
		end

		local current = get_section_ss_backend(s)
		if current then
			has_ss_node = true
			if current ~= preferred then
				needs_refresh = true
				return false
			end
		end
	end)

	return has_ss_node and needs_refresh
end

local function is_mihomo_subscribe_node(section)
	if not section then
		return false
	end
	-- 如果不使用 Mihomo 模式，返回 false
	if not should_use_mihomo_mode() then
		return false
	end
	if section.type == "clash" and section.clash_path and tostring(section.clash_path):match("%.mihomo%.yaml$") then
		return true
	end
	if section.type == "ssr" then
		return true
	end
	if section.type == "ss" or section.type == "ss-rust" then
		return true
	end
	if section.type == "v2ray" and (
		section.v2ray_protocol == "vmess"
		or section.v2ray_protocol == "vless"
		or section.v2ray_protocol == "shadowsocks"
		or section.v2ray_protocol == "trojan"
		or section.v2ray_protocol == "hysteria2"
		or section.v2ray_protocol == "hy2"
		or section.v2ray_protocol == "snell"
	) then
		return true
	end
	if section.type == "tuic" then
		return true
	end
	return false
end

local function group_needs_mihomo_subscribe_refresh(groupHash)
	if not should_use_mihomo_mode() then
		return false
	end

	local needs_refresh = false
	ucic:foreach(name, uciType, function(s)
		if s.grouphashkey == groupHash then
			if is_mihomo_subscribe_node(s) and s.type ~= "clash" then
				needs_refresh = true
				return false
			end
			if s.type == "clash" and s.clash_path and tostring(s.clash_path):match("%.anytls%.yaml$") then
				needs_refresh = true
				return false
			end
		end
	end)

	return needs_refresh
end

local function preserve_unselected_groups(selected_hashes)
	local preserved = {}

	ucic:foreach(name, uciType, function(s)
		local groupHash = s.grouphashkey
		if groupHash and groupHash ~= "" and not selected_hashes[groupHash] and not preserved[groupHash] then
			preserved[groupHash] = true
			loadOldNodes(groupHash)
		end
	end)
end

-- 获取 groupHash 的公共函数（预留函数）
local function get_group_hash(url, fetch_url)
	if should_use_mihomo_mode() then
		return md5(fetch_url)
	else
		return md5(url)
	end
end

local execute = function()
	local updated = false
	local selected_hashes = {}

	for _, item in ipairs(subscribe_items) do
		local fetch_url = build_convert_url(item.url)
		if should_use_mihomo_mode() then
			selected_hashes[md5(fetch_url)] = true
		else
			selected_hashes[md5(item.url)] = true
		end
	end

	if target_subscribe_sid ~= "" then
		preserve_unselected_groups(selected_hashes)
	end

	for _, item in ipairs(subscribe_items) do
		local url = item.url
		local fetch_url, converted = build_convert_url(url)
		local raw, new_md5
		local groupHash
		local yaml_removed_count = 0
		
		if should_use_mihomo_mode() then
			raw, new_md5 = curl(fetch_url, user_agent)
			if isClashYAML(raw) then
				raw, yaml_removed_count = filterClashYamlRaw(raw)
				if yaml_removed_count and yaml_removed_count > 0 then
					new_md5 = md5_string(raw)
				end
			end
			groupHash = md5(fetch_url)
		else
			raw, new_md5 = curl(url, user_agent)
			groupHash = md5(url)
		end
		
		log("raw 长度: "..#raw)
		local old_md5 = read_old_md5(groupHash)

		log("处理订阅: " .. url)
		if should_use_mihomo_mode() and converted then
			log("使用订阅转换模板: " .. template_url)
			log("转换服务: " .. convert_address)
		end
		if should_use_mihomo_mode() and yaml_removed_count and yaml_removed_count > 0 then
			log("Clash/Mihomo YAML 已按订阅过滤关键词移除节点数量: " .. tostring(yaml_removed_count))
		end
		log("groupHash: " .. groupHash)
		log("old_md5: " .. tostring(old_md5))
		log("new_md5: " .. tostring(new_md5))

		local backend_refresh = group_needs_ss_backend_refresh(groupHash)
		local mihomo_subscribe_refresh = group_needs_mihomo_subscribe_refresh(groupHash)
		local missing_saved_nodes = old_md5 and new_md5 == old_md5 and not group_has_saved_nodes(groupHash)
		
		if #raw == 0 then
			log(url .. ': 获取内容为空')
			loadOldNodes(groupHash)
		elseif old_md5 and new_md5 == old_md5 and not backend_refresh and not mihomo_subscribe_refresh and not missing_saved_nodes then
			log("订阅未变化, 跳过无需更新的订阅: " .. url)
			-- 防止 diff 阶段误删未更新订阅节点
			loadOldNodes(groupHash)
			--ucic:foreach(name, uciType, function(s)
			--	if s.grouphashkey == groupHash and s.hashkey then
			--		cache[groupHash][s.hashkey] = s
			--		tinsert(nodeResult[index], s)
			--	end
			--end)
		else
			if backend_refresh and old_md5 and new_md5 == old_md5 then
				log("检测到 SS 后端偏好变化，强制重建订阅节点: " .. url)
			end
			if mihomo_subscribe_refresh and old_md5 and new_md5 == old_md5 then
				log("检测到可迁移订阅节点，强制重建为 Mihomo 总节点: " .. url)
			end
			if missing_saved_nodes then
				log("订阅内容未变化但本地节点不存在，强制重建订阅节点: " .. url)
			end
			updated = true
			-- 保存更新后的 MD5 值到以 groupHash 为标识的临时文件中，用于下次订阅更新时进行对比
			write_new_md5(groupHash, new_md5)

			cache[groupHash] = {}
			tinsert(nodeResult, {})
			local index = #nodeResult
			local nodes, szType
			local is_clash_subscription = false

			if isClashYAML(raw) then
				is_clash_subscription = true
				local result = processClashSubscription(fetch_url)
				if result and check_filer(result) then
					log('过滤 Clash 总节点: ' .. result.alias)
				elseif result and not cache[groupHash][result.hashkey] then
					result.grouphashkey = groupHash
					table.insert(nodeResult[index], result)
					cache[groupHash][result.hashkey] = result
					log('成功导入 Clash 总节点: ' .. result.alias)
				else
					log('丢弃无效 Clash 总节点: ' .. url)
				end
			-- SSD 似乎是这种格式 ssd:// 开头的
			elseif raw:find('ssd://') then
				szType = 'ssd'
				local nEnd = select(2, raw:find('ssd://'))
				nodes = base64Decode(raw:sub(nEnd + 1, #raw))
				nodes = jsonParse(nodes)
				local extra = {
					airport = nodes.airport,
					port = nodes.port,
					encryption = nodes.encryption,
					password = nodes.password
				}
				local servers = {}
				-- SS里面包着 干脆直接这样
				for _, server in ipairs(nodes.servers or {}) do
					tinsert(servers, setmetatable(server, {__index = extra}))
				end
				nodes = servers
			-- SS SIP008 直接使用 Json 格式
			elseif jsonParse(raw) then
				nodes = jsonParse(raw).servers or jsonParse(raw)
				if nodes[1] and nodes[1].server and nodes[1].method then
					szType = 'sip008'
				end
			-- 其他 base64 格式
			else
				-- ssd 外的格式
				nodes = split(base64Decode(raw):gsub("\r\n", "\n"), "\n")
			end

			if not is_clash_subscription and not szType and type(nodes) == "table" then
				local anytls_nodes = {}
				local normal_nodes = {}
				for _, node in ipairs(nodes) do
					local line = trim(node or "")
					if line:match("^anytls://") then
						local parsed = parseAnytlsShare(line:gsub("^anytls://", ""))
						if parsed then
							table.insert(anytls_nodes, anytls_to_mihomo_node(parsed))
						end
					elseif line ~= "" then
						table.insert(normal_nodes, node)
					end
				end

				if #anytls_nodes > 0 then
					for _, parsed in ipairs(anytls_nodes) do
						table.insert(normal_nodes, parsed)
					end
				end

				nodes = normal_nodes
			end

			-- 临时存储该订阅解析出的节点（带原始别名）
			local groupRawNodes = {}

			if not is_clash_subscription then
				for _, v in ipairs(nodes) do
					if v and (type(v) == "table" or not string.match(v, "^%s*$")) then
						xpcall(function()
							local result
							if type(v) == "table" then
								result = v
							elseif szType then
								result = processData(szType, v)
							elseif not szType then
								local node = trim(v)
								-- 一些奇葩的链接用"&amp;"、"&lt;"当做"&"，"#"前后带空格
								local link = node:gsub("&[a-zA-Z]+;", "&"):gsub("%s*#%s*", "#")
								local dat = split(link, "://")
								if dat and dat[1] and dat[2] then
									local dat3 = ""
									if dat[3] then
										dat3 = "://" .. dat[3]
									end
									if dat[1] == 'ss' or dat[1] == 'trojan' or dat[1] == 'tuic' or dat[1] == 'snell' then
										result = processData(dat[1], dat[2] .. dat3)
									else
										result = processData(dat[1], base64Decode(dat[2]))
									end
								end
							else
								log('跳过未知类型: ' .. szType)
							end
							-- log(result)
							if result then
								local filtered = check_filer(result)
								-- 中文做地址的 也没有人拿中文域名搞，就算中文域也有Puny Code SB 机场
								local invalid = not result.server or not result.server_port
									or (result.type ~= "clash" and result.server == "127.0.0.1")
									or result.alias == "NULL"
									or (result.type ~= "clash" and result.server:match("[^0-9a-zA-Z%-_%.%s]"))
									or cache[groupHash][result.hashkey]
								if filtered then
									log('过滤节点: ' .. result.alias)
								elseif invalid then
									log('丢弃无效节点: ' .. result.alias)
								else
									-- 暂存节点
									table.insert(groupRawNodes, result)
								end
							end
						end, function(err)
							log(string.format("解析节点出错: %s\n原始数据: %s", tostring(err), tostring(v)))
						end)
					end
				end
			end

			-- 传统模式：对 groupRawNodes 进行组内编号
			if not should_use_mihomo_mode() then
				local freq = {}
				for _, node in ipairs(groupRawNodes) do
					local raw = node.raw_alias or ""
					if raw ~= "" then
						freq[raw] = (freq[raw] or 0) + 1
					end
				end
				local aliasCount = {}
				for _, node in ipairs(groupRawNodes) do
					local raw = node.raw_alias or ""
					if raw ~= "" then
						if freq[raw] and freq[raw] > 1 then
							local count = (aliasCount[raw] or 0) + 1
							aliasCount[raw] = count
							node.alias = raw .. "_" .. count
						else
							node.alias = raw
						end
					end
					-- 清理临时字段
					node.raw_alias = nil
				end
			end

			local mihomo_nodes = {}
			local legacy_nodes = {}
			
			-- 只有当 should_use_mihomo_mode() 为 true 时才尝试分组
			if should_use_mihomo_mode() then
				for _, node in ipairs(groupRawNodes) do
					if has_mihomo and can_group_into_mihomo(node) then
						mihomo_nodes[#mihomo_nodes + 1] = node
					else
						legacy_nodes[#legacy_nodes + 1] = node
					end
				end
			else
				-- 传统模式：所有节点作为普通节点
				for _, node in ipairs(groupRawNodes) do
					legacy_nodes[#legacy_nodes + 1] = node
				end
			end

			if #mihomo_nodes > 0 then
				local parsed_url = URL.parse(url)
				local alias = item.alias ~= "" and item.alias or ("Mihomo_" .. ((parsed_url and parsed_url.host) or groupHash))
				local local_path = string.format("%s/%s.mihomo.yaml", local_clash_dir, groupHash)
				local yaml, proxy_count = buildMihomoSubscribeYaml(mihomo_nodes, "Proxy")

				if yaml and proxy_count > 0 then
					nixio.fs.mkdirr(local_clash_dir)
					nixio.fs.writefile(local_path, yaml)

					local result = processLocalClashSubscription(local_path, alias)
					if result and not cache[groupHash][result.hashkey] then
						result.grouphashkey = groupHash
						table.insert(nodeResult[index], result)
						cache[groupHash][result.hashkey] = result
						log('成功导入 Mihomo 总节点: ' .. result.alias .. '，包含节点数量: ' .. proxy_count)
					end
				else
					log('Mihomo 总节点生成失败，回退为普通订阅节点。')
					for _, node in ipairs(mihomo_nodes) do
						legacy_nodes[#legacy_nodes + 1] = node
					end
				end
			end

			for _, node in ipairs(legacy_nodes) do
				node.grouphashkey = groupHash
				table.insert(nodeResult[index], node)
				cache[groupHash][node.hashkey] = node
			end

			if not should_use_mihomo_mode() then
				log('成功解析节点数量: ' .. #groupRawNodes)
			end
		end
	end

	-- 输出日志并判断是否需要进行 diff
	if not updated then
		log("订阅未变化，无需更新节点信息。")
		log('保留手动添加的节点。')
		return
	end

	-- diff 阶段
	if next(nodeResult) == nil then
		log("更新失败，没有可用的节点信息")
		return
	end
	local add, del = 0, 0
	ucic:foreach(name, uciType, function(old)
		if old.grouphashkey or old.hashkey then -- 没有 hash 的不参与删除
			if not nodeResult[old.grouphashkey] or not nodeResult[old.grouphashkey][old.hashkey] then
				ucic:delete(name, old['.name'])
				del = del + 1
			else
				local dat = nodeResult[old.grouphashkey][old.hashkey]
				-- 标记一下
				ucic:tset(name, old['.name'], dat)
				setmetatable(nodeResult[old.grouphashkey][old.hashkey], {__index = {_ignore = true}})
			end
		else
			if not old.alias then
				if old.server or old.server_port then
					old.alias = old.server .. ':' .. old.server_port
					log('忽略手动添加的节点: ' .. old.alias)
				else
					ucic:delete(name, old['.name'])
				end
			else
				log('忽略手动添加的节点: ' .. old.alias)
			end
		end
	end)
	
	-- 生成 sid
	-- 记录已使用编号
	local used_sid = {}
	local next_sid = 1
	-- 检查已有 section
	ucic:foreach(name, uciType, function(s)
		local num = s[".name"]:match("^cfg(%x%x)")  -- 提取两位十六进制序号
		if num then
			local n = tonumber(num, 16)
			used_sid[n] = true
		end
	end)
	-- 获取下一个可用编号（O(1)）
	local function get_next_sid()
		while used_sid[next_sid] do
			next_sid = next_sid + 1
		end
		used_sid[next_sid] = true
		return next_sid
	end

	local sid = ucic:add(name, uciType)
	ucic:delete(name, sid)
	for _, v in ipairs(nodeResult) do
		for _, vv in ipairs(v) do
			if not vv._ignore then
				--local sid = ucic:add(name, uciType)
				if sid then
					local suffix = sid:sub(-4)
					--ucic:delete(name, sid)
					local id = get_next_sid()
					local cfgid = string.format("cfg%02x%s", id, suffix)
					local section = ucic:section(name, uciType, cfgid)
					if section then
						ucic:tset(name, section, vv)
						ucic:set(name, section, "switch_enable", switch)
						add = add + 1
					end
				end
			end
		end
	end
	ucic:commit(name)
	-- 如果原有服务器节点已经不见了就尝试换为第一个节点
	local globalServer = ucic:get_first(name, 'global', 'global_server', '')
	if globalServer ~= "nil" then
		local firstServer = ucic:get_first(name, uciType)
		if firstServer then
			if not ucic:get(name, globalServer) then
				luci.sys.call("/etc/init.d/" .. name .. " stop > /dev/null 2>&1 &")
				ucic:commit(name)
				ucic:set(name, ucic:get_first(name, 'global'), 'global_server', firstServer)
				ucic:commit(name)
				log('当前主服务器节点已被删除，正在自动更换为第一个节点。')
				luci.sys.call("/etc/init.d/" .. name .. " start > /dev/null 2>&1 &")
			else
				log('维持当前主服务器节点。')
				luci.sys.call("/etc/init.d/" .. name .. " restart > /dev/null 2>&1 &")
			end
		else
			log('没有服务器节点了，停止服务')
			luci.sys.call("/etc/init.d/" .. name .. " stop > /dev/null 2>&1 &")
		end
	end
	log('新增节点数量: ' .. add .. ', 删除节点数量: ' .. del)
	log('订阅更新成功')
end

if subscribe_items and #subscribe_items > 0 then
	if proxy == "1" then
		log("当前订阅模式: 通过代理订阅")
	else
		log("当前订阅模式: 不通过代理订阅")
	end
	
	-- 记录当前使用的订阅模式
	if should_use_mihomo_mode() then
		log("订阅模式: Mihomo 总节点模式")
	else
		log("订阅模式: 传统节点模式")
	end
	
	local direct_bypass = create_direct_subscribe_bypass()
	if direct_bypass then
		direct_bypass:apply()
	end
	xpcall(execute, function(e)
		log(e)
		log(debug.traceback())
		log('发生错误, 正在尝试恢复服务状态')
		local firstServer = ucic:get_first(name, uciType)
		if firstServer then
			luci.sys.call("/etc/init.d/" .. name .. " restart > /dev/null 2>&1 &") -- 不加&的话日志会出现的更早
			log('重启服务成功')
		else
			luci.sys.call("/etc/init.d/" .. name .. " stop > /dev/null 2>&1 &") -- 不加&的话日志会出现的更早
			log('停止服务成功')
		end
	end)
	if direct_bypass then
		direct_bypass:cleanup()
	end
end
