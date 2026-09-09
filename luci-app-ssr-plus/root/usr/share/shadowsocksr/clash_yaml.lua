#!/usr/bin/lua

require "nixio"
require "nixio.fs"
require "luci.model.uci"

local ok_lyaml, lyaml = pcall(require, "lyaml")
if not ok_lyaml then
	io.stderr:write("lyaml_not_found\n")
	os.exit(2)
end

local uci = require "luci.model.uci".cursor()
local ok_jsonc, jsonc = pcall(require, "luci.jsonc")

local dns_mode = uci:get_first("shadowsocksr", "global", "pdnsd_enable", "0")
if dns_mode == nil or dns_mode == "" then
	dns_mode = "0"
end

local enable_fake_ip = uci:get_first("shadowsocksr", "server_subscribe", "enable_fake_ip", "")
if enable_fake_ip == nil or enable_fake_ip == "" then
	enable_fake_ip = "0"
end

-- ==================== 基础工具函数 =================================
-- ==================== Basic Utility Functions ====================

local function read_file(path)
	local data = nixio.fs.readfile(path)
	if not data or data == "" then
		return nil
	end
	return data
end

local function write_file(path, data)
	return nixio.fs.writefile(path, data)
end

local function load_yaml(path)
	local raw = read_file(path)
	if not raw then
		return nil, "read_failed"
	end

	local ok, parsed = pcall(lyaml.load, raw)
	if not ok or type(parsed) ~= "table" then
		return nil, "parse_failed"
	end

	return parsed
end

local function quote_nameserver_policy_keys(rendered)
	rendered = rendered:gsub("[^\n]*", function(line)
		local indent = line:match("^(%s*)geosite:geolocation%-!cn:%s*$")
		if indent then
			return indent .. '"geosite:geolocation-!cn":'
		end

		indent = line:match("^(%s*)geosite:cn,private,apple:%s*$")
		if indent then
			return indent .. '"geosite:cn,private,apple":'
		end

		return line
	end)

	return rendered
end

local function dump_yaml(path, data)
	local ok, rendered = pcall(lyaml.dump, { data })
	if not ok or not rendered then
		return nil, "dump_failed"
	end

	rendered = quote_nameserver_policy_keys(rendered)

	write_file(path, rendered)
	return true
end

local function split_filter_words(text)
	local items = {}
	for part in tostring(text or ""):gmatch("[^/]+") do
		if part ~= "" then
			items[#items + 1] = part
		end
	end
	return items
end

local function trim(value)
	return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
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

local function split_csv(value)
	local items = {}
	for part in tostring(value or ""):gmatch("[^,%s]+") do
		items[#items + 1] = part
	end
	return items
end

local function split_host_port(value)
	local text = tostring(value or "")
	if text == "" then
		return "", ""
	end
	local host, port = text:match("^%[(.-)%]:(%d+)$")
	if host and port then
		return host, port
	end
	host, port = text:match("^(.-):(%d+)$")
	if host and port then
		return host, port
	end
	return text, ""
end

local function split_alpn(value)
	local items = {}
	for part in tostring(value or ""):gmatch("[^,;|%s]+") do
		items[#items + 1] = part
	end
	return items
end

local function split_local_addresses(value)
	local items = {}
	if type(value) == "table" then
		for _, item in ipairs(value) do
			if item and item ~= "" then
				items[#items + 1] = tostring(item)
			end
		end
	elseif value and value ~= "" then
		for item in tostring(value):gmatch("[^,%s]+") do
			items[#items + 1] = item
		end
	end
	return items
end

local function split_wireguard_addresses(value)
	local ip, ipv6
	for _, item in ipairs(split_local_addresses(value)) do
		if item:find(":", 1, true) then
			ipv6 = ipv6 or item
		else
			ip = ip or item
		end
	end
	return ip, ipv6
end

local function first_nonempty(...)
	for i = 1, select("#", ...) do
		local value = select(i, ...)
		if value ~= nil and value ~= "" then
			return value
		end
	end
	return nil
end

local function clone_table(src)
	if type(src) ~= "table" then
		return nil
	end

	local dst = {}

	for k, v in pairs(src) do
		if type(v) == "table" then
			dst[k] = clone_table(v)
		else
			dst[k] = v
		end
	end

	return dst
end

local function deep_merge(dst, src)
	if type(dst) ~= "table" or type(src) ~= "table" then
		return src
	end

	for k, v in pairs(src) do
		if type(v) == "table" and type(dst[k]) == "table" then
			dst[k] = deep_merge(dst[k], v)
		else
			dst[k] = v
		end
	end

	return dst
end

local function read_clash_client_rules_csv(sid)
	local rows = {}
	sid = trim(sid)
	if sid == "" then
		return rows
	end

	local csv_path = string.format("/etc/ssrplus/clash/%s.csv", sid)
	local raw = read_file(csv_path)
	if not raw or raw == "" then
		return rows
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
					rows[#rows + 1] = {
						enabled = cols[1],
						ip_addr = trim(cols[2] or ""),
						policy_group = trim(cols[3] or ""),
						remarks = trim(cols[4] or ""),
						client_mac = trim(cols[5] or "")
					}
				end
			end
		end
	end

	return rows
end

local function get_server_field(sid, option, default)
	local value = uci:get("shadowsocksr", sid, option)
	if value == nil or value == "" then
		return default
	end
	return value
end

-- ==================== ECH 配置获取函数 =========================================
-- ==================== ECH Configuration Fetching Function ====================

local function fetch_ech_config(domain, dns_server)
	if not domain or domain == "" or not dns_server or dns_server == "" then
		return nil
	end
    
	local server = dns_server
		:gsub("^[a-zA-Z0-9%+%-%.]+://", "")
		:gsub("/.*$", "")
		:gsub(":%d+$", "")
    
	if server == "" then
		return nil
	end
    
	local cmd = string.format("dig +short TYPE65 %s @%s 2>/dev/null", domain, server)
	local handle = io.popen(cmd)
	if not handle then
		return nil
	end

	local output = handle:read("*a")
	handle:close()
    
	local ech = output:match("ech=([^%s]+)")
	if ech then
		return ech  -- 返回 base64 编码的 ECH 值
	end
    
	return nil
end

local function get_filter_aaaa()
	local value = uci:get_first("shadowsocksr", "global", "filter_aaaa", "1")
	if value == nil or value == "" then
		value = uci:get_first("shadowsocksr", "global", "mosdns_ipv6", "1")
	end
	return value
end

local function bool_enabled(value)
	return value == "1" or value == 1 or value == true or value == "true"
end

local function bool_default(value, default)
	if value == nil or value == "" then
		return default
	end
	return bool_enabled(value)
end

local function number_or_nil(value)
	if value == nil or value == "" then
		return nil
	end
	return tonumber(value)
end

local function string_or_nil(value)
	if value == nil or value == "" then
		return nil
	end
	return tostring(value)
end

local function get_uptime_ms()
	local f = io.open("/proc/uptime", "r")
	if f then
		local line = f:read("*l")
		f:close()
		if line then
			local sec, frac = line:match("^(%d+)%.(%d+)")
			if sec and frac then
				frac = (frac .. "00"):sub(1, 3)
				return tonumber(sec) * 1000 + tonumber(frac)
			end
		end
	end
	return os.time() * 1000
end

local function load_list_file(file_path)
	local list = {}
	local file = io.open(file_path, "r")
	if not file then
		return nil
	end

	for line in file:lines() do
		line = line:match("^%s*(.-)%s*$")
		if line ~= "" and not line:match("^#") then
			table.insert(list, line)
		end
	end
	file:close()
	return #list > 0 and list or nil
end

-- ==================== DNS 相关函数 ==============================
-- ==================== DNS-related Functions ====================

local function format_dns_server(proxy)
	if not proxy or proxy == "" then
		return proxy
	end

	local scheme, rest = proxy:match("^([a-zA-Z0-9%+%-%.]+)://(.+)$")
	if scheme then
		scheme = scheme:lower()
		if scheme == "tls" or scheme == "dot" then
			if not rest:match(":%d+$") then
				rest = rest .. ":853"
			end
			return "tls://" .. rest
		elseif scheme == "https" or scheme == "doh" or scheme == "dohl" or scheme == "doq" or scheme == "doql" then
			local host, path = rest:match("^([^/]+)(.*)$")
			host = host or rest
			path = path or ""
			if path == "" or path == "/" then
				path = "/dns-query"
			end
			return "https://" .. host .. path
		elseif scheme == "tcp" or scheme == "udp" then
			if not rest:match(":%d+$") then
				rest = rest .. ":53"
			end
			return scheme .. "://" .. rest
		else
			return proxy
		end
	end

	local host, port = proxy:match("^([^:]+):(%d+)$")
	if host and port then
		if port == "853" then
			return "tls://" .. host .. ":853"
		elseif port == "443" then
			return "https://" .. host .. "/dns-query"
		elseif port == "53" then
			return host
		else
			return "udp://" .. host .. ":" .. port
		end
	end

	if proxy:match("[a-zA-Z]") and not proxy:match("[^%w%.%-]") then
		local path = ""
		if not proxy:match("/") then
			path = "/dns-query"
		end
		return "https://" .. proxy .. path
	end

	return proxy
end

local function get_fastest_dns()
	local dns_list = {
		"223.5.5.5", "119.29.29.29",
		"114.114.114.114", "180.76.76.76",
		"114.114.115.115", "223.6.6.6",
		"1.2.4.8", "1.12.12.12",
		"101.226.4.6", "180.184.1.1",
	}
	local test_domain = "www.baidu.com"
	local valid_dns_results = {}

	for _, dns in ipairs(dns_list) do
		local start_time = get_uptime_ms()

		local cmd = string.format(
			"timeout 2 nslookup %s %s 2>/dev/null",
			test_domain,
			dns
		)

		local f = io.popen(cmd)
		if f then
			local output = f:read("*a") or ""
			f:close()

			local elapsed = get_uptime_ms() - start_time
			local parsed_ip
			for ip in output:gmatch("Address%s*%d*%s*:%s*(%d+%.%d+%.%d+%.%d+)") do
				if ip ~= dns then
					parsed_ip = ip
					break
				end
			end
			local is_success =
				parsed_ip
				and not output:match("[Cc]an't find")
				and not output:match("[Tt]imed out")
				and not output:match("[Nn]o servers could be reached")
			if is_success and elapsed >= 0 and elapsed < 2500 then
				table.insert(valid_dns_results, {
					dns = dns,
					latency = elapsed,
				})
			end
		end
	end

	table.sort(valid_dns_results, function(a, b)
		return a.latency < b.latency
	end)

	local result = {}
	local used = {}

	for i = 1, math.min(3, #valid_dns_results) do
		local dns = valid_dns_results[i].dns
		table.insert(result, dns)
		used[dns] = true
	end

	local fallbacks = {
		"223.5.5.5",
		"119.29.29.29",
		"114.114.114.114",
	}

	for _, dns in ipairs(fallbacks) do
		if #result >= 3 then
			break
		end

		if not used[dns] then
			table.insert(result, dns)
			used[dns] = true
		end
	end

	return result
end

local function get_forward_dns_list()
	local forward = uci:get_first("shadowsocksr", "global", "tunnel_forward", "8.8.4.4:53")
	if not forward or forward == "" then
		forward = "8.8.4.4:53"
	end

	local forward_list = {}
	local used = {}

	for proxy in tostring(forward):gmatch("[^%s,;]+") do
		if proxy ~= "" then
			local formatted = format_dns_server(proxy)
			if not used[formatted] then
				table.insert(forward_list, formatted)
				used[formatted] = true
			end
		end
	end

	if #forward_list == 0 then
		forward_list = { format_dns_server(forward) }
	end

	return forward_list
end

local function build_dns_upstreams()
	local fastest_list = get_fastest_dns()
	local nameserver_list = {}
	local proxy_server_list = {}
	--local used_dns = {}

	local proxy_server_list = {
		"https://cn.ali-oss.cn:44443/dns-query/6dafe708-d9d6-48cc-a768-e6ed3018a9ec",
		"https://hk.ali-oss.cn:44443/dns-query/6dafe708-d9d6-48cc-a768-e6ed3018a9ec"
	}
	--local used_dns = {}

	for _, dns_ip in ipairs(fastest_list) do
		local formatted = format_dns_server(dns_ip)
		table.insert(nameserver_list, formatted)
	--
	--	if not used_dns[dns_ip] then
	--		table.insert(proxy_server_list, dns_ip)
	--		used_dns[dns_ip] = true
	--	end
	end

	return {
		["respect-rules"] = true,
		["nameserver"] = nameserver_list,
		["proxy-server-nameserver"] = proxy_server_list
	}
end

local function build_dns_section(dns_mode, user_dns, is_external_dns)
	local result
	local has_user_dns = type(user_dns) == "table" and next(user_dns)

	if not has_user_dns then
		if is_external_dns then
			return { enable = false }
		end
		result = {
			enable = true,
			listen = "127.0.0.1:5335"
		}
	else
		result = clone_table(user_dns)
		result.enable = true
	end

	if enable_fake_ip == "1" then
		result["enhanced-mode"] = "fake-ip"
		-- if not result["fake-ip-range"] then
		-- 	result["fake-ip-range"] = "198.18.0.1/16"
		-- end
		-- Must match the range redirected by ssr-rules; a value supplied by the
		-- subscription would leave those redirects pointing at the wrong network.
		-- result["fake-ip-range"] = nil
		result["fake-ip-range"] = "198.18.0.1/16"
		if not result["fake-ip-filter"] then
			local filter_file = "/etc/ssrplus/fake_ip_filter.list"
			local loaded_filter = load_list_file(filter_file) or { "*.lan", "*.local", "time.*.com", "ntp.*.com" }
			if loaded_filter then
				result["fake-ip-filter"] = loaded_filter
			end
		end
		if result["use-hosts"] == nil then
			result["use-hosts"] = true
		end

		-- if not result["fallback"] then
		-- 	result["fallback"] = get_forward_dns_list()
		-- end
		result["fallback"] = nil
		result["fallback"] = get_forward_dns_list()

		if not result["default-nameserver"] then
			result["default-nameserver"] = get_fastest_dns()
		end
		if result["respect-rules"] == nil then
			result["respect-rules"] = true
		end
		if not result["fallback-filter"] then
			local domain_file = "/etc/ssrplus/fallback_domain.list"
			local domain_list = load_list_file(domain_file) or { "+.google.com", "+.facebook.com", "+.youtube.com" }
			local ipcidr_file = "/etc/ssrplus/fallback_ipcidr.list"
			local ipcidr_list = load_list_file(ipcidr_file) or { "240.0.0.0/4" }
			result["fallback-filter"] = {
				domain = domain_list,
				ipcidr = ipcidr_list,
				geoip = true,
				["geoip-code"] = "CN"
			}
		else
			if result["fallback-filter"].geosite then
				result["fallback-filter"].geosite = nil
			end
		end

		-- if not result["nameserver-policy"] then
		-- 	result["nameserver-policy"] = {}
		-- end
		-- if not result["nameserver-policy"]["geosite:gfw"] then
		-- 	result["nameserver-policy"]["geosite:gfw"] = result["fallback"] or get_forward_dns_list()
		-- end
		-- if not result["nameserver-policy"]["geosite:cn,private,apple"] then
		-- 	result["nameserver-policy"]["geosite:cn,private,apple"] = get_fastest_dns()
		-- end
		result["nameserver-policy"] = nil
		result["nameserver-policy"] = {
			["geosite:geolocation-!cn"] = result["fallback"] or get_forward_dns_list(),
			["geosite:cn,private,apple"] = get_fastest_dns()
		}
		
	else
		result["enhanced-mode"] = "redir-host"
		result["fake-ip-range"] = nil
		result["fake-ip-filter"] = nil
		result["use-hosts"] = nil
		result["fallback"] = nil
		result["respect-rules"] = nil
		result["fallback-filter"] = nil
		result["nameserver-policy"] = nil
	end

	local upstreams = build_dns_upstreams()
	for k, v in pairs(upstreams) do
		if k == "proxy-server-nameserver" then
			result[k] = v
		elseif result[k] == nil then
			result[k] = v
		end
	end

	if dns_mode == "7" then
		-- Must match the address dnsmasq forwards to; a value supplied by the
		-- subscription would make every forwarded query hit a closed port.
		-- result.listen = nil
		result.listen = "127.0.0.1:5335"
	else
		result.listen = nil
	end

	if result.ipv6 == nil then
		result.ipv6 = get_filter_aaaa() ~= "1"
	end

	return result
end

-- ==================== 配置处理函数 ============================================
-- ==================== Configuration Processing Functions ====================

local function has_proxy_sections(doc)
	return type(doc.proxies) == "table" or type(doc["proxy-providers"]) == "table"
end

local function validate(path)
	local doc = load_yaml(path)
	if not doc then
		return false
	end
	return has_proxy_sections(doc)
end

local function filter(path, filter_words)
	local doc, err = load_yaml(path)
	if not doc then
		io.stderr:write(err or "parse_failed", "\n")
		return false
	end

	local words = split_filter_words(filter_words)
	if #words == 0 then
		return true
	end

	local removed = {}
	local proxies = {}
	for _, proxy in ipairs(doc.proxies or {}) do
		local name = tostring(proxy.name or "")
		local matched = false
		for _, word in ipairs(words) do
			if name:find(word, 1, true) then
				matched = true
				removed[name] = true
				break
			end
		end
		if not matched then
			proxies[#proxies + 1] = proxy
		end
	end
	doc.proxies = proxies

	for _, group in ipairs(doc["proxy-groups"] or {}) do
		if type(group.proxies) == "table" then
			local kept = {}
			for _, name in ipairs(group.proxies) do
				if not removed[tostring(name)] then
					kept[#kept + 1] = name
				end
			end
			group.proxies = kept
		end
	end

	local count = 0
	for _ in pairs(removed) do
		count = count + 1
	end

	dump_yaml(path, doc)
	io.stdout:write(tostring(count), "\n")
	return true
end

local function strip_runtime_conflicts(doc)
	doc.tun = nil
	doc.listeners = nil
	doc["redir-port"] = nil
	doc["tproxy-port"] = nil
	doc["socks-port"] = nil
	doc["mixed-port"] = nil
	doc.port = nil
	doc["external-controller"] = nil
	doc.secret = nil
	doc["allow-lan"] = nil
	if type(doc.dns) == "table" then
		doc.dns["fake-ip-range"] = nil
		doc.dns["fake-ip-filter"] = nil
	end
end

local function apply_sniffer_config(doc, enable_fake_ip)
	if type(doc) ~= "table" then return end
	if enable_fake_ip == "1" then
		if not doc.sniffer then
			doc.sniffer = {
				enable = true,
				["override-destination"] = true,
				sniff = {
					HTTP = { 
						ports = { 80, "8080-8880" }
					},
					TLS = { 
						ports = { 443, 8443 }
					},
					QUIC = { 
						ports = { 443, 8443 }
					}
				},
				["skip-domain"] = { "Mijia Cloud", "dlg.io.mi.com" },
				["parse-pure-ip"] = false
			}
		end
	else
		doc.sniffer = nil
	end
end

local function group_requires_candidates(group)
	local gtype = tostring(group and group.type or ""):lower()
	return gtype == "select"
		or gtype == "fallback"
		or gtype == "load-balance"
		or gtype == "url-test"
		or gtype == "relay"
end

local function has_nonempty_sequence(value)
	return type(value) == "table" and next(value) ~= nil
end

local function fill_empty_proxy_groups(doc)
	local changed = 0
	for _, group in ipairs(doc["proxy-groups"] or {}) do
		if type(group) == "table"
			and group_requires_candidates(group)
			and not has_nonempty_sequence(group.proxies)
			and not has_nonempty_sequence(group.use)
		then
			group.proxies = { "DIRECT" }
			changed = changed + 1
		end
	end
	return changed
end

local function strip_incompatible_script_rules(doc)
	local kept = {}
	local removed = 0
	local has_script_rule = false

	for _, rule in ipairs(doc.rules or {}) do
		local text = tostring(rule or "")
		if text:match("^SCRIPT,") then
			removed = removed + 1
		else
			kept[#kept + 1] = rule
			if text:match("^SCRIPT,") then
				has_script_rule = true
			end
		end
	end

	if removed > 0 then
		doc.rules = kept
	end

	if not has_script_rule then
		doc.script = nil
	end

	return removed
end

local function merge_rules_with_direct(existing_rules)
	local new_rules = {}
	local existing_set = {}
	local match_rule = nil

	if existing_rules then
		for _, rule in ipairs(existing_rules) do
			local clean_rule = rule:match("^%s*(.-)%s*$") or rule
			
			if clean_rule:upper():find("^MATCH,") then
				if not match_rule then
					match_rule = clean_rule
				end
			else
				if not existing_set[clean_rule] and clean_rule ~= "" then
					table.insert(new_rules, clean_rule)
					existing_set[clean_rule] = true
				end
			end
		end
	end

	table.insert(new_rules, match_rule or "MATCH,PROXY")

	return new_rules
end

-- ==================== Shadowsocks 插件处理函数 =====================================
-- ==================== Shadowsocks Plugin Processing Functions ====================

local function parse_plugin_opts(value)
	local result = {}
	for part in tostring(value or ""):gmatch("[^;]+") do
		local key, val = part:match("^%s*([^=]+)=?(.*)%s*$")
		if key and key ~= "" then
			result[key] = val or ""
		end
	end
	return result
end

local function parse_plugin_headers(plugin_opts)
	local headers = {}
	local raw_headers = pick_plugin_opt(plugin_opts, "headers", "header")

	if raw_headers and ok_jsonc and jsonc then
		local decoded = jsonc.parse(raw_headers)
		if type(decoded) == "table" then
			for key, value in pairs(decoded) do
				headers[tostring(key)] = tostring(value)
			end
		end
	end

	if raw_headers and next(headers) == nil then
		for part in tostring(raw_headers):gmatch("[^|,]+") do
			local key, value = part:match("^%s*([^=:]+)%s*[:=]%s*(.-)%s*$")
			if key and key ~= "" and value and value ~= "" then
				headers[key] = value
			end
		end
	end

	for key, value in pairs(plugin_opts) do
		local header_name = key:match("^headers[%.:](.+)$")
			or key:match("^header[%.:](.+)$")
			or key:match("^header_(.+)$")
		if header_name and header_name ~= "" and value ~= "" then
			headers[header_name] = value
		end
	end

	return next(headers) and headers or nil
end

local function get_plugin_client_fingerprint(sid, plugin_opts)
	return string_or_nil(
		pick_plugin_opt(
			plugin_opts,
			"client-fingerprint",
			"client_fingerprint",
			"fingerprint"
		) or get_server_field(sid, "fingerprint", "")
	)
end

local function normalize_plugin_name(plugin)
	local value = tostring(plugin or ""):lower()
	if value == "" or value == "none" then
		return ""
	end
	if value == "simple-obfs" then
		return "obfs-local"
	end
	if value == "obfs" then
		return "obfs-local"
	end
	if value == "shadowtls" then
		return "shadow-tls"
	end
	if value == "gost" then
		return "gost-plugin"
	end
	if value == "kcp-tun" then
		return "kcptun"
	end
	return value
end

local function pick_plugin_opt(plugin_opts, ...)
	for i = 1, select("#", ...) do
		local key = select(i, ...)
		local value = plugin_opts[key]
		if value ~= nil and value ~= "" then
			return value
		end
	end
	return nil
end

local function build_shadowsocks_plugin(proxy, sid)
	local plugin = normalize_plugin_name(get_server_field(sid, "plugin", ""))
	local plugin_opts = parse_plugin_opts(get_server_field(sid, "plugin_opts", ""))

	if plugin == "" then
		return
	end

	if plugin == "obfs-local" then
		proxy.plugin = "obfs"
		proxy["plugin-opts"] = {
			mode = pick_plugin_opt(plugin_opts, "obfs", "mode") or "http",
			host = string_or_nil(pick_plugin_opt(plugin_opts, "obfs-host", "obfs_host", "host"))
		}
		return
	end

	if plugin == "v2ray-plugin" or plugin == "xray-plugin" then
		proxy.plugin = "v2ray-plugin"
		proxy["plugin-opts"] = {
			mode = pick_plugin_opt(plugin_opts, "mode") or "websocket",
			tls = bool_default(pick_plugin_opt(plugin_opts, "tls"), false),
			fingerprint = string_or_nil(pick_plugin_opt(plugin_opts, "fingerprint")),
			["skip-cert-verify"] = bool_default(pick_plugin_opt(plugin_opts, "skip-cert-verify", "skip_cert_verify", "insecure"), false),
			host = string_or_nil(pick_plugin_opt(plugin_opts, "host")),
			path = string_or_nil(pick_plugin_opt(plugin_opts, "path")),
			mux = bool_default(pick_plugin_opt(plugin_opts, "mux"), false),
			headers = parse_plugin_headers(plugin_opts),
			["v2ray-http-upgrade"] = bool_default(pick_plugin_opt(plugin_opts, "v2ray-http-upgrade", "v2ray_http_upgrade"), false)
		}
		return
	end

	if plugin == "gost-plugin" then
		proxy.plugin = "gost-plugin"
		proxy["plugin-opts"] = {
			mode = pick_plugin_opt(plugin_opts, "mode") or "websocket",
			tls = bool_default(pick_plugin_opt(plugin_opts, "tls"), false),
			fingerprint = string_or_nil(pick_plugin_opt(plugin_opts, "fingerprint")),
			["skip-cert-verify"] = bool_default(pick_plugin_opt(plugin_opts, "skip-cert-verify", "skip_cert_verify", "insecure"), false),
			host = string_or_nil(pick_plugin_opt(plugin_opts, "host")),
			path = string_or_nil(pick_plugin_opt(plugin_opts, "path")),
			mux = bool_default(pick_plugin_opt(plugin_opts, "mux"), false),
			headers = parse_plugin_headers(plugin_opts)
		}
		return
	end

	if plugin == "shadow-tls" then
		local host, port = split_host_port(pick_plugin_opt(plugin_opts, "host") or "")
		local version
		if plugin_opts.v3 == "1" or plugin_opts.version == "3" then
			version = 3
		elseif plugin_opts.v2 == "1" or plugin_opts.version == "2" then
			version = 2
		elseif plugin_opts.v1 == "1" or plugin_opts.version == "1" then
			version = 1
		end
		proxy.plugin = "shadow-tls"
		proxy["client-fingerprint"] = get_plugin_client_fingerprint(sid, plugin_opts)
		proxy["plugin-opts"] = {
			host = host ~= "" and host or nil,
			port = number_or_nil(port),
			password = string_or_nil(pick_plugin_opt(plugin_opts, "passwd", "password")),
			version = version
		}
		return
	end

	if plugin == "restls" then
		proxy.plugin = "restls"
		proxy["client-fingerprint"] = get_plugin_client_fingerprint(sid, plugin_opts)
		proxy["plugin-opts"] = {
			host = string_or_nil(pick_plugin_opt(plugin_opts, "host")),
			password = string_or_nil(pick_plugin_opt(plugin_opts, "passwd", "password")),
			["version-hint"] = string_or_nil(pick_plugin_opt(plugin_opts, "version-hint", "version_hint")),
			["restls-script"] = string_or_nil(pick_plugin_opt(plugin_opts, "restls-script", "restls_script"))
		}
		return
	end

	if plugin == "kcptun" then
		proxy.plugin = "kcptun"
		proxy["plugin-opts"] = {
			key = string_or_nil(pick_plugin_opt(plugin_opts, "key", "passwd", "password")),
			crypt = string_or_nil(pick_plugin_opt(plugin_opts, "crypt")),
			mode = string_or_nil(pick_plugin_opt(plugin_opts, "mode")),
			conn = number_or_nil(pick_plugin_opt(plugin_opts, "conn")),
			autoexpire = number_or_nil(pick_plugin_opt(plugin_opts, "autoexpire")),
			scavengettl = number_or_nil(pick_plugin_opt(plugin_opts, "scavengettl")),
			mtu = number_or_nil(pick_plugin_opt(plugin_opts, "mtu")),
			ratelimit = number_or_nil(pick_plugin_opt(plugin_opts, "ratelimit")),
			sndwnd = number_or_nil(pick_plugin_opt(plugin_opts, "sndwnd")),
			rcvwnd = number_or_nil(pick_plugin_opt(plugin_opts, "rcvwnd")),
			datashard = number_or_nil(pick_plugin_opt(plugin_opts, "datashard")),
			parityshard = number_or_nil(pick_plugin_opt(plugin_opts, "parityshard")),
			dscp = number_or_nil(pick_plugin_opt(plugin_opts, "dscp")),
			nocomp = bool_default(pick_plugin_opt(plugin_opts, "nocomp"), false),
			acknodelay = bool_default(pick_plugin_opt(plugin_opts, "acknodelay"), false),
			nodelay = number_or_nil(pick_plugin_opt(plugin_opts, "nodelay")),
			interval = number_or_nil(pick_plugin_opt(plugin_opts, "interval")),
			resend = number_or_nil(pick_plugin_opt(plugin_opts, "resend")),
			sockbuf = number_or_nil(pick_plugin_opt(plugin_opts, "sockbuf")),
			smuxver = number_or_nil(pick_plugin_opt(plugin_opts, "smuxver")),
			smuxbuf = number_or_nil(pick_plugin_opt(plugin_opts, "smuxbuf")),
			framesize = number_or_nil(pick_plugin_opt(plugin_opts, "framesize")),
			streambuf = number_or_nil(pick_plugin_opt(plugin_opts, "streambuf")),
			keepalive = number_or_nil(pick_plugin_opt(plugin_opts, "keepalive"))
		}
		return
	end

	proxy.plugin = plugin
	if next(plugin_opts) then
		proxy["plugin-opts"] = plugin_opts
	end
end

local function build_kcptun_plugin(proxy, sid)
	if not bool_enabled(get_server_field(sid, "kcp_enable", "0")) then
		return
	end

	proxy.plugin = "kcptun"
	proxy.port = tonumber(get_server_field(sid, "kcp_port", "0")) or proxy.port
	proxy["plugin-opts"] = {
		key = get_server_field(sid, "kcp_password", ""),
		mode = "fast",
		mtu = 1350
	}
end

-- ==================== V2Ray 节点构建函数 =====================================
-- ==================== V2Ray Node Construction Functions ====================

local function parse_wireguard_reserved(sid)
	local raw = get_server_field(sid, "reserved", nil)
	local values = {}
	local bytes = {}

	if raw == nil or raw == "" then
		return nil
	end
	if type(raw) == "table" then
		values = raw
	else
		values = { raw }
	end
	for _, item in ipairs(values) do
		local text = tostring(item or "")
		if text ~= "" then
			if not text:match("[^%d,]+") then
				for byte in text:gmatch("%d+") do
					bytes[#bytes + 1] = tonumber(byte)
				end
			else
				local decoded = nixio.bin.b64decode(text)
				if decoded then
					for i = 1, #decoded do
						bytes[#bytes + 1] = decoded:byte(i)
					end
				end
			end
		end
	end
	return #bytes > 0 and bytes or nil
end

local function apply_v2ray_tls_options(proxy, sid)
	local tls = get_server_field(sid, "tls", "0")
	local reality = get_server_field(sid, "reality", "0")
	if tls ~= "1" and reality ~= "1" then
		return
	end

	proxy.tls = true
	proxy.servername = string_or_nil(get_server_field(sid, "tls_host", ""))
	proxy["client-fingerprint"] = string_or_nil(get_server_field(sid, "fingerprint", ""))
	proxy.fingerprint = string_or_nil(get_server_field(sid, "tls_CertSha", ""))
	proxy["skip-cert-verify"] = bool_enabled(get_server_field(sid, "insecure", "0"))

	local alpn = split_alpn(get_server_field(sid, "tls_alpn", ""))
	if #alpn > 0 then
		proxy.alpn = alpn
	end

	if reality == "1" then
		proxy["reality-opts"] = {
			["public-key"] = string_or_nil(get_server_field(sid, "reality_publickey", "")),
			["short-id"] = string_or_nil(get_server_field(sid, "reality_shortid", "")),
			["support-x25519mlkem768"] = bool_enabled(get_server_field(sid, "enable_mldsa65verify", "0"))
		}
	end

	-- ECH 配置处理
	if get_server_field(sid, "enable_ech", "0") == "1" then
		local raw_ech_cfg = get_server_field(sid, "ech_config", "")
		local raw_domain = get_server_field(sid, "ech_domain", "")
		local ech_base64_result = nil
		local query_server_name = nil

		if raw_ech_cfg:find("+") then
			local domain_part, dns_part = raw_ech_cfg:match("^([^+]+)%+(.+)$")
			if domain_part and dns_part then
				ech_base64_result = string_or_nil(fetch_ech_config(domain_part, dns_part))
				query_server_name = domain_part
			end
		elseif raw_ech_cfg:match("^https?://") and raw_domain and raw_domain ~= "" then
			ech_base64_result = string_or_nil(fetch_ech_config(raw_domain, raw_ech_cfg))
			query_server_name = raw_domain
		elseif raw_ech_cfg:match("^[A-Za-z0-9+/=]+$") then
			ech_base64_result = raw_ech_cfg
			if raw_domain and raw_domain ~= "" then
				query_server_name = raw_domain
			end
		end

		if ech_base64_result then
			proxy["ech-opts"] = {
				enable = true,
				config = ech_base64_result
			}
			if query_server_name and query_server_name ~= "" then
				proxy["ech-opts"]["query-server-name"] = query_server_name
			end
		end
	end
end

local function apply_v2ray_transport_options(proxy, sid)
	local transport = get_server_field(sid, "transport", "raw")
	if transport == "raw" or transport == "tcp" or transport == "" then
		return
	end

	if transport == "ws" then
		proxy.network = "ws"
		proxy["ws-opts"] = {
			path = string_or_nil(get_server_field(sid, "ws_path", "")),
			headers = first_nonempty(get_server_field(sid, "ws_host", ""), get_server_field(sid, "tls_host", "")) and {
				Host = first_nonempty(get_server_field(sid, "ws_host", ""), get_server_field(sid, "tls_host", ""))
			} or nil
		}
	elseif transport == "httpupgrade" then
		proxy.network = "ws"
		proxy["ws-opts"] = {
			path = string_or_nil(get_server_field(sid, "httpupgrade_path", "")),
			headers = first_nonempty(get_server_field(sid, "httpupgrade_host", ""), get_server_field(sid, "tls_host", "")) and {
				Host = first_nonempty(get_server_field(sid, "httpupgrade_host", ""), get_server_field(sid, "tls_host", ""))
			} or nil,
			["v2ray-http-upgrade"] = true
		}
	elseif transport == "h2" then
		local host = first_nonempty(get_server_field(sid, "h2_host", ""), get_server_field(sid, "tls_host", ""))
		proxy.network = "h2"
		proxy["h2-opts"] = {
			host = host and split_alpn(host) or nil,
			path = string_or_nil(get_server_field(sid, "h2_path", ""))
		}
	elseif transport == "grpc" then
		proxy.network = "grpc"
		proxy["grpc-opts"] = {
			["grpc-service-name"] = string_or_nil(get_server_field(sid, "serviceName", ""))
		}
	elseif transport == "xhttp" and proxy.type == "vless" then
		proxy.network = "xhttp"
		proxy["xhttp-opts"] = {
			path = string_or_nil(get_server_field(sid, "xhttp_path", "")),
			host = string_or_nil(get_server_field(sid, "xhttp_host", "")),
			mode = string_or_nil(get_server_field(sid, "xhttp_mode", ""))
		}
	end
end

local function apply_trojan_tls_options(proxy, sid)
	proxy.sni = string_or_nil(get_server_field(sid, "tls_host", ""))
	proxy["client-fingerprint"] = string_or_nil(get_server_field(sid, "fingerprint", ""))
	proxy.fingerprint = string_or_nil(get_server_field(sid, "tls_CertSha", ""))
	proxy["skip-cert-verify"] = bool_enabled(get_server_field(sid, "insecure", "0"))

	local alpn = split_alpn(get_server_field(sid, "tls_alpn", ""))
	if #alpn > 0 then
		proxy.alpn = alpn
	end

	if get_server_field(sid, "reality", "0") == "1" then
		proxy["reality-opts"] = {
			["public-key"] = string_or_nil(get_server_field(sid, "reality_publickey", "")),
			["short-id"] = string_or_nil(get_server_field(sid, "reality_shortid", ""))
		}
	end

	-- ECH 配置处理
	if get_server_field(sid, "enable_ech", "0") == "1" then
		local raw_ech_cfg = get_server_field(sid, "ech_config", "")
		local raw_domain = get_server_field(sid, "ech_domain", "")
		local ech_base64_result = nil
		local query_server_name = nil

		if raw_ech_cfg:find("+") then
			local domain_part, dns_part = raw_ech_cfg:match("^([^+]+)%+(.+)$")
			if domain_part and dns_part then
				ech_base64_result = string_or_nil(fetch_ech_config(domain_part, dns_part))
				query_server_name = domain_part
			end
		elseif raw_ech_cfg:match("^https?://") and raw_domain and raw_domain ~= "" then
			ech_base64_result = string_or_nil(fetch_ech_config(raw_domain, raw_ech_cfg))
			query_server_name = raw_domain
		elseif raw_ech_cfg:match("^[A-Za-z0-9+/=]+$") then
			ech_base64_result = raw_ech_cfg
			if raw_domain and raw_domain ~= "" then
				query_server_name = raw_domain
			end
		end

		if ech_base64_result then
			proxy["ech-opts"] = {
				enable = true,
				config = ech_base64_result
			}
			if query_server_name and query_server_name ~= "" then
				proxy["ech-opts"]["query-server-name"] = query_server_name
			end
		end
	end
end

local function can_mihomo_handle_v2ray_transport(protocol, sid)
	local transport = get_server_field(sid, "transport", "raw")
	if transport == "" or transport == "raw" or transport == "tcp" then
		if get_server_field(sid, "tcp_guise", "none") == "http" then
			return false
		end
		return true
	end
	if protocol == "socks" or protocol == "http" then
		return false
	end
	if transport == "ws" or transport == "httpupgrade" or transport == "h2" or transport == "grpc" then
		return true
	end
	return protocol == "vless" and transport == "xhttp"
end

local function build_v2ray_mihomo_proxy(sid)
	local node_type = get_server_field(sid, "type", "")
	local protocol = get_server_field(sid, "v2ray_protocol", "vmess")
	local proxy = {
		name = sid,
		server = get_server_field(sid, "server", ""),
		port = tonumber(get_server_field(sid, "server_port", "0")) or 0,
		udp = true,
		tfo = bool_enabled(get_server_field(sid, "fast_open", "0"))
	}

	if node_type == "socks5" then
		proxy.type = "socks5"
		if get_server_field(sid, "auth_enable", "0") == "1" then
			proxy.username = string_or_nil(get_server_field(sid, "username", ""))
			proxy.password = string_or_nil(get_server_field(sid, "password", ""))
		end
	elseif protocol == "vmess" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "vmess"
		proxy.uuid = first_nonempty(get_server_field(sid, "vmess_id", ""), get_server_field(sid, "vmess_uuid", "")) or ""
		proxy.alterId = tonumber(get_server_field(sid, "alter_id", "0")) or 0
		proxy.cipher = first_nonempty(get_server_field(sid, "security", ""), get_server_field(sid, "vmess_method", ""), "auto")
		apply_v2ray_tls_options(proxy, sid)
		apply_v2ray_transport_options(proxy, sid)
	elseif protocol == "vless" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "vless"
		proxy.uuid = get_server_field(sid, "vmess_id", "")
		proxy.flow = string_or_nil(get_server_field(sid, "tls_flow", ""))
		proxy.encryption = get_server_field(sid, "vless_encryption", "")
		apply_v2ray_tls_options(proxy, sid)
		apply_v2ray_transport_options(proxy, sid)
	elseif protocol == "trojan" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "trojan"
		proxy.password = get_server_field(sid, "password", "")
		apply_trojan_tls_options(proxy, sid)
		apply_v2ray_transport_options(proxy, sid)
	elseif protocol == "shadowsocks" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "ss"
		proxy.cipher = get_server_field(sid, "encrypt_method_ss", "none")
		proxy.password = get_server_field(sid, "password", "")
		build_shadowsocks_plugin(proxy, sid)
	elseif protocol == "hysteria2" then
		proxy.type = "hysteria2"
		proxy.password = get_server_field(sid, "hy2_auth", "")
		proxy.ports = string_or_nil(get_server_field(sid, "port_range", ""))
		proxy.up = string_or_nil(get_server_field(sid, "uplink_capacity", "")) and (get_server_field(sid, "uplink_capacity", "") .. " Mbps") or nil
		proxy.down = string_or_nil(get_server_field(sid, "downlink_capacity", "")) and (get_server_field(sid, "downlink_capacity", "") .. " Mbps") or nil
		proxy.sni = string_or_nil(get_server_field(sid, "tls_host", ""))
		proxy.fingerprint = string_or_nil(get_server_field(sid, "tls_CertSha", ""))
		proxy["skip-cert-verify"] = bool_enabled(get_server_field(sid, "insecure", "0"))
		local alpn = split_alpn(get_server_field(sid, "tls_alpn", ""))
		if #alpn > 0 then
			proxy.alpn = alpn
		end
		if get_server_field(sid, "flag_obfs", "0") == "1" then
			local obfs_type = get_server_field(sid, "obfs_type", "")
			proxy.obfs = string_or_nil(obfs_type)
			proxy["obfs-password"] = string_or_nil(get_server_field(sid, "salamander", ""))
			if obfs_type == "gecko" then
				local min = tonumber(get_server_field(sid, "obfs_MinPacketSize", "")) or 512
				local max = tonumber(get_server_field(sid, "obfs_MaxPacketSize", "")) or 1200
				if min <= 0 or min > max or max > 2048 then
					min = 512
					max = 1200
				end
				proxy["obfs-min-packet-size"] = min
				proxy["obfs-max-packet-size"] = max
			end
		end
	elseif protocol == "socks" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "socks5"
		if get_server_field(sid, "socks_ver", "5") ~= "5" then
			return nil
		end
		if get_server_field(sid, "auth_enable", "0") == "1" then
			proxy.username = string_or_nil(get_server_field(sid, "username", ""))
			proxy.password = string_or_nil(get_server_field(sid, "password", ""))
		end
		apply_v2ray_tls_options(proxy, sid)
	elseif protocol == "http" then
		if not can_mihomo_handle_v2ray_transport(protocol, sid) then
			return nil
		end
		proxy.type = "http"
		if get_server_field(sid, "auth_enable", "0") == "1" then
			proxy.username = string_or_nil(get_server_field(sid, "username", ""))
			proxy.password = string_or_nil(get_server_field(sid, "password", ""))
		end
		apply_v2ray_tls_options(proxy, sid)
	elseif protocol == "wireguard" then
		local ip, ipv6 = split_wireguard_addresses(get_server_field(sid, "local_addresses", ""))
		proxy.type = "wireguard"
		proxy["private-key"] = get_server_field(sid, "private_key", "")
		proxy["public-key"] = get_server_field(sid, "peer_pubkey", "")
		proxy["pre-shared-key"] = string_or_nil(get_server_field(sid, "preshared_key", ""))
		proxy.ip = ip
		proxy.ipv6 = ipv6
		proxy["allowed-ips"] = split_local_addresses(get_server_field(sid, "allowedips", "0.0.0.0/0"))
		proxy.reserved = parse_wireguard_reserved(sid)
		proxy["persistent-keepalive"] = number_or_nil(get_server_field(sid, "keepaliveperiod", ""))
		proxy.mtu = number_or_nil(get_server_field(sid, "mtu", ""))
	elseif protocol == "snell" then
		proxy.type = "snell"
		proxy.psk = get_server_field(sid, "snell_psk", "")
		proxy.version = number_or_nil(get_server_field(sid, "snell_version", ""))
		local obfs_mode = string_or_nil(get_server_field(sid, "snell_obfs", ""))
		local obfs_host = string_or_nil(get_server_field(sid, "snell_obfs_host", ""))
		if obfs_mode or obfs_host then
			proxy["obfs-opts"] = {
				mode = obfs_mode,
				host = obfs_host
			}
		end
	else
		return nil
	end

	if not proxy.server or proxy.server == "" or not proxy.port or proxy.port == 0 then
		return nil
	end
	if proxy.type == "snell" and (not proxy.psk or proxy.psk == "") then
		return nil
	end
	return proxy
end

-- ==================== 节点运行时文档构建函数 ==============================================
-- ==================== Node Runtime Document Construction Functions ====================

local function build_single_proxy_runtime_doc(proxy, local_port, socks_port, mode)
	local listen_port = tonumber(local_port)
	local socks_listen = tonumber(socks_port)
	local mode_str = tostring(dns_mode or "")
	local is_ext_dns = (mode_str ~= "7")

	local doc = {
		["allow-lan"] = true,
		["bind-address"] = "0.0.0.0",
		mode = "rule",
		["log-level"] = "silent",
		["find-process-mode"] = "off",
		["unified-delay"] = true,
		["tcp-concurrent"] = true,
		["routing-mark"] = 255,
		proxies = { proxy },
		["proxy-groups"] = {
			{
				name = "PROXY",
				type = "select",
				proxies = { proxy.name }
			}
		},
		rules = { "MATCH,PROXY" },
		tun = { enable = false },
		profile = { ["store-selected"] = true },
		dns = build_dns_section(dns_mode, nil, is_ext_dns)
	}

	if mode == "socks" then
		doc["socks-port"] = listen_port
	else
		doc["redir-port"] = listen_port
		doc["tproxy-port"] = listen_port
		if socks_listen and socks_listen > 0 then
			doc["socks-port"] = socks_listen
		end
	end
	return doc
end

local function build_tuic_runtime_doc(sid, local_port, socks_port, mode)
	local server = get_server_field(sid, "server", "")
	local server_port = tonumber(get_server_field(sid, "server_port", "0")) or 0
	local tuic_ip = get_server_field(sid, "tuic_ip", "")
	local tls_host = get_server_field(sid, "tls_host", "")
	local ipstack_prefer = get_server_field(sid, "ipstack_prefer", "")
	local mode_str = tostring(dns_mode or "")
	local is_ext_dns = (mode_str ~= "7")

	local proxy = {
		name = sid,
		type = "tuic",
		server = server,
		port = server_port,
		uuid = get_server_field(sid, "tuic_uuid", ""),
		password = get_server_field(sid, "tuic_passwd", ""),
		["udp-relay-mode"] = get_server_field(sid, "udp_relay_mode", "native"),
		["congestion-controller"] = get_server_field(sid, "congestion_control", "cubic"),
		["skip-cert-verify"] = bool_enabled(get_server_field(sid, "insecure", "0")),
		["disable-sni"] = bool_enabled(get_server_field(sid, "disable_sni", "0")),
		["reduce-rtt"] = bool_enabled(get_server_field(sid, "zero_rtt_handshake", "0"))
	}

	if tuic_ip ~= "" then
		proxy.ip = tuic_ip
	end
	if tls_host ~= "" then
		proxy.sni = tls_host
	end

	local alpn = split_csv(get_server_field(sid, "tuic_alpn", ""))
	if #alpn > 0 then
		proxy.alpn = alpn
	end

	local heartbeat = tonumber(get_server_field(sid, "heartbeat", "0"))
	if heartbeat and heartbeat > 0 then
		proxy["heartbeat-interval"] = heartbeat * 1000
	end

	local timeout = tonumber(get_server_field(sid, "timeout", "0"))
	if timeout and timeout > 0 then
		proxy["request-timeout"] = timeout * 1000
	end

	local max_udp_packet_size = tonumber(get_server_field(sid, "tuic_max_package_size", "0"))
	if max_udp_packet_size and max_udp_packet_size > 0 then
		proxy["max-udp-relay-packet-size"] = max_udp_packet_size
	end

	if ipstack_prefer ~= "" then
		proxy["ip-version"] = ipstack_prefer == "v6first" and "ipv6-prefer" or "ipv4-prefer"
	end

	local listen_port = tonumber(local_port)
	local socks_listen = tonumber(socks_port)

	local doc = {
		["allow-lan"] = true,
		["bind-address"] = "0.0.0.0",
		mode = "rule",
		["log-level"] = "silent",
		["find-process-mode"] = "off",
		["unified-delay"] = true,
		["tcp-concurrent"] = true,
		["routing-mark"] = 255,
		proxies = { proxy },
		["proxy-groups"] = {
			{
				name = "PROXY",
				type = "select",
				proxies = { sid }
			}
		},
		rules = { "MATCH,PROXY" },
		tun = { enable = false },
		profile = { ["store-selected"] = true },
		dns = build_dns_section(dns_mode, nil, is_ext_dns)
	}

	if mode == "socks" then
		doc["socks-port"] = listen_port
	else
		doc["redir-port"] = listen_port
		doc["tproxy-port"] = listen_port
		if socks_listen and socks_listen > 0 then
			doc["socks-port"] = socks_listen
		end
	end

	return doc
end

local function build_shadowsocks_runtime_doc(sid, local_port, socks_port, mode)
	local server = get_server_field(sid, "server", "")
	local server_port = tonumber(get_server_field(sid, "server_port", "0")) or 0
	local method = get_server_field(sid, "encrypt_method_ss", "none")
	local password = get_server_field(sid, "password", "")
	local mode_str = tostring(dns_mode or "")
	local is_ext_dns = (mode_str ~= "7")
	local proxy = {
		name = sid,
		type = "ss",
		server = server,
		port = server_port,
		cipher = method,
		password = password,
		udp = true,
		tfo = bool_enabled(get_server_field(sid, "fast_open", "0"))
	}

	if get_server_field(sid, "type", "") == "ss" then
		build_kcptun_plugin(proxy, sid)
	end
	if proxy.plugin == nil then
		build_shadowsocks_plugin(proxy, sid)
	end

	local doc = {
		["allow-lan"] = true,
		["bind-address"] = "0.0.0.0",
		mode = "rule",
		["log-level"] = "silent",
		["find-process-mode"] = "off",
		["unified-delay"] = true,
		["tcp-concurrent"] = true,
		["routing-mark"] = 255,
		proxies = { proxy },
		["proxy-groups"] = {
			{
				name = "PROXY",
				type = "select",
				proxies = { sid }
			}
		},
		rules = { "MATCH,PROXY" },
		tun = { enable = false },
		profile = { ["store-selected"] = true },
		dns = build_dns_section(dns_mode, nil, is_ext_dns)
	}

	local listen_port = tonumber(local_port)
	local socks_listen = tonumber(socks_port)
	if mode == "socks" then
		doc["socks-port"] = listen_port
	else
		doc["redir-port"] = listen_port
		doc["tproxy-port"] = listen_port
		if socks_listen and socks_listen > 0 then
			doc["socks-port"] = socks_listen
		end
	end

	return doc
end

-- ==================== 服务端文档构建函数 ===========================================
-- ==================== Server Document Construction Functions ====================

local function build_shadowsocks_server_doc(sid)
	local server_port = tonumber(get_server_field(sid, "server_port", "0")) or 0
	local method = get_server_field(sid, "encrypt_method_ss", "aes-128-gcm")
	local password = get_server_field(sid, "password", "")
	local listener = {
		name = sid,
		type = "shadowsocks",
		listen = "::",
		port = server_port,
		cipher = method,
		password = password,
		udp = true,
		tfo = bool_enabled(get_server_field(sid, "fast_open", "0"))
	}

	local plugin = normalize_plugin_name(get_server_field(sid, "plugin", ""))
	if plugin == "obfs-local" then
		local plugin_opts = parse_plugin_opts(get_server_field(sid, "plugin_opts", ""))
		listener.obfs = plugin_opts.obfs or plugin_opts.mode or "http"
		listener.obfs_opts = {
			mode = plugin_opts.obfs or plugin_opts.mode or "http",
			host = plugin_opts["obfs-host"] or plugin_opts.obfs_host or plugin_opts.host or nil
		}
	end

	return {
		["allow-lan"] = true,
		["bind-address"] = "*",
		["log-level"] = "silent",
		["find-process-mode"] = "off",
		listeners = { listener }
	}
end

local function build_mihomo_listener_doc(sid)
	local ltype = get_server_field(sid, "type", "")
	local server_port = tonumber(get_server_field(sid, "server_port", "0")) or 0
	local listener = {
		name = sid,
		type = ltype,
		listen = "::",
		port = server_port
	}

	if ltype == "vmess" then
		listener.users = {
			{
				username = "1",
				uuid = get_server_field(sid, "uuid", ""),
				alterId = tonumber(get_server_field(sid, "alter_id", "0")) or 0
			}
		}
	elseif ltype == "vless" then
		listener.users = {
			{
				username = "1",
				uuid = get_server_field(sid, "uuid", ""),
				flow = string_or_nil(get_server_field(sid, "flow", ""))
			}
		}
	elseif ltype == "trojan" then
		listener.users = {
			{
				username = "1",
				password = get_server_field(sid, "trojan_password", "")
			}
		}
	elseif ltype == "shadowsocks" then
		listener.type = "shadowsocks"
		listener.cipher = get_server_field(sid, "security", "chacha20-ietf-poly1305")
		listener.password = get_server_field(sid, "ss_password", "")
		listener.udp = true
	else
		return nil
	end

	local network = get_server_field(sid, "network", "tcp")
	if network == "ws" then
		listener["ws-path"] = string_or_nil(get_server_field(sid, "ws_path", "/"))
	elseif network == "grpc" then
		listener["grpc-service-name"] = string_or_nil(get_server_field(sid, "grpc_service", ""))
	end

	local cert = get_server_field(sid, "certpath", "")
	local key = get_server_field(sid, "keypath", "")
	if cert ~= "" and key ~= "" then
		listener.certificate = cert
		listener["private-key"] = key
	end

	return {
		["allow-lan"] = true,
		["bind-address"] = "*",
		["log-level"] = "silent",
		["find-process-mode"] = "off",
		listeners = { listener }
	}
end

-- ==================== 生成配置函数 ============================================
-- ==================== Configuration Generation Functions ====================

local function generate_tuic_runtime(sid, output_path, local_port, socks_port, mode)
	local doc = build_tuic_runtime_doc(sid, local_port, socks_port, mode)
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	return true
end

local function generate_shadowsocks_runtime(sid, output_path, local_port, socks_port, mode)
	local doc = build_shadowsocks_runtime_doc(sid, local_port, socks_port, mode)
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	return true
end

local function generate_v2ray_runtime(sid, output_path, local_port, socks_port, mode)
	local proxy = build_v2ray_mihomo_proxy(sid)
	if not proxy then
		io.stderr:write("unsupported_or_invalid_v2ray_node\n")
		return false
	end
	local doc = build_single_proxy_runtime_doc(proxy, local_port, socks_port, mode)
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	return true
end

local function generate_shadowsocks_server(sid, output_path)
	local doc = build_shadowsocks_server_doc(sid)
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	return true
end

local function generate_mihomo_listener(sid, output_path)
	local doc = build_mihomo_listener_doc(sid)
	if not doc then
		io.stderr:write("unsupported_listener\n")
		return false
	end
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	return true
end

-- ==================== 主要功能函数 ======================================
-- ==================== Main Functionality Functions ====================

local function prepare(input_path, output_path)
	local doc, err = load_yaml(input_path)
	if not doc then
		io.stderr:write(err or "parse_failed", "\n")
		return false
	end
	if not has_proxy_sections(doc) then
		io.stderr:write("missing_proxy_sections\n")
		return false
	end

	local user_dns = nil
	if type(doc.dns) == "table" and next(doc.dns) then
		user_dns = clone_table(doc.dns)
	end

	strip_runtime_conflicts(doc)
	local filled_groups = fill_empty_proxy_groups(doc)
	local stripped_rules = strip_incompatible_script_rules(doc)
	
	local dns_config = build_dns_section(dns_mode, user_dns, false)
	if dns_config and next(dns_config) then
		doc.dns = dns_config
	end

	doc.rules = merge_rules_with_direct(doc.rules)
	apply_sniffer_config(doc, enable_fake_ip)
	
	if not dump_yaml(output_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	io.stdout:write(string.format("filled_groups=%d stripped_script_rules=%d\n", filled_groups, stripped_rules))
	return true
end

local function merge(raw_path, overlay_path, output_path)
	local raw_doc, raw_err = load_yaml(raw_path)
	if not raw_doc then
		io.stderr:write(raw_err or "parse_failed", "\n")
		return false
	end

	local overlay_doc, overlay_err = load_yaml(overlay_path)
	if not overlay_doc then
		io.stderr:write(overlay_err or "parse_failed", "\n")
		return false
	end

	local user_dns = nil
	if type(raw_doc.dns) == "table" and next(raw_doc.dns) then
		user_dns = clone_table(raw_doc.dns)
	end

	strip_runtime_conflicts(raw_doc)
	local filled_groups = fill_empty_proxy_groups(raw_doc)
	local stripped_rules = strip_incompatible_script_rules(raw_doc)

	if user_dns then
		if dns_mode ~= "7" then
			overlay_doc.dns = nil
		end
	end

	local merged = deep_merge(raw_doc, overlay_doc)
	if user_dns then
		merged.dns = build_dns_section(dns_mode, user_dns, false)
	elseif type(merged.dns) == "table" and next(merged.dns) then
		merged.dns = build_dns_section(dns_mode, merged.dns, false)
	else
		merged.dns = build_dns_section(dns_mode, nil, false)
	end

	merged.rules = merge_rules_with_direct(merged.rules)
	apply_sniffer_config(merged, enable_fake_ip)

	if not dump_yaml(output_path, merged) then
		io.stderr:write("dump_failed\n")
		return false
	end
	io.stdout:write(string.format("filled_groups=%d stripped_script_rules=%d\n", filled_groups, stripped_rules))
	return true
end

local function append_client_policy_rules(runtime_path, sid)
	local doc, err = load_yaml(runtime_path)
	if not doc then
		io.stderr:write(err or "parse_failed", "\n")
		return false
	end

	local valid_policies = {}
	for _, proxy in ipairs(doc.proxies or {}) do
		if type(proxy) == "table" and proxy.name and proxy.name ~= "" then
			valid_policies[tostring(proxy.name)] = true
		end
	end
	for _, group in ipairs(doc["proxy-groups"] or {}) do
		if type(group) == "table" and group.name and group.name ~= "" then
			valid_policies[tostring(group.name)] = true
		end
	end

	local custom_rules = {}
	for _, section in ipairs(read_clash_client_rules_csv(sid)) do
		if tostring(section.enabled or "0") == "1" then
			local ip_addr = tostring(section.ip_addr or "")
			local policy_group = tostring(section.policy_group or "")
			if ip_addr ~= "" and policy_group ~= "" and valid_policies[policy_group] then
				if not ip_addr:find("/", 1, true) then
					ip_addr = ip_addr .. "/32"
				end
				custom_rules[#custom_rules + 1] = string.format("SRC-IP-CIDR,%s,%s", ip_addr, policy_group)
			end
		end
	end

	if #custom_rules == 0 then
		io.stdout:write("client_rules=0\n")
		return true
	end

	local existing_rules = {}
	for _, rule in ipairs(doc.rules or {}) do
		local text = tostring(rule or "")
		if not text:match("^SRC%-IP%-CIDR,") then
			table.insert(existing_rules, rule)
		end
	end

	local new_rules = {}
	local existing_set = {}

	for _, rule in ipairs(custom_rules) do
		if not existing_set[rule] then
			table.insert(new_rules, rule)
			existing_set[rule] = true
		end
	end

	for _, rule in ipairs(existing_rules) do
		if not existing_set[rule] then
			table.insert(new_rules, rule)
			existing_set[rule] = true
		end
	end

	doc.rules = merge_rules_with_direct(new_rules)

	if not dump_yaml(runtime_path, doc) then
		io.stderr:write("dump_failed\n")
		return false
	end
	io.stdout:write(string.format("client_rules=%d\n", #custom_rules))
	return true
end

-- ==================== 命令行入口 ====================
-- ==================== Command-line Entry Point ====================

local action = arg[1]
if action == "validate" then
	os.exit(validate(arg[2]) and 0 or 1)
elseif action == "filter" then
	os.exit(filter(arg[2], arg[3]) and 0 or 1)
elseif action == "prepare" then
	os.exit(prepare(arg[2], arg[3]) and 0 or 1)
elseif action == "merge" then
	os.exit(merge(arg[2], arg[3], arg[4]) and 0 or 1)
elseif action == "append_client_policy_rules" then
	os.exit(append_client_policy_rules(arg[2], arg[3]) and 0 or 1)
elseif action == "tuic" then
	os.exit(generate_tuic_runtime(arg[2], arg[3], arg[4], arg[5], arg[6]) and 0 or 1)
elseif action == "ss" then
	os.exit(generate_shadowsocks_runtime(arg[2], arg[3], arg[4], arg[5], arg[6]) and 0 or 1)
elseif action == "v2ray" then
	os.exit(generate_v2ray_runtime(arg[2], arg[3], arg[4], arg[5], arg[6]) and 0 or 1)
elseif action == "ss_server" then
	os.exit(generate_shadowsocks_server(arg[2], arg[3]) and 0 or 1)
elseif action == "v2ray_server" then
	os.exit(generate_mihomo_listener(arg[2], arg[3]) and 0 or 1)
else
	io.stderr:write("usage: clash_yaml.lua validate <yaml> | filter <yaml> <words> | prepare <input> <output> | merge <raw> <overlay> <output> | append_client_policy_rules <runtime_yaml> <sid> | tuic <sid> <output> <local_port> [socks_port] [mode] | ss <sid> <output> <local_port> [socks_port] [mode] | v2ray <sid> <output> <local_port> [socks_port] [mode] | ss_server <sid> <output> | v2ray_server <sid> <output>\n")
	os.exit(1)
end
