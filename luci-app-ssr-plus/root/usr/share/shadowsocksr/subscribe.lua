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
local URL = require "url"
local cache = {}
local nodeResult = setmetatable({}, {__index = cache}) -- update result
local name = 'shadowsocksr'
local uciType = 'servers'
local ucic = require "luci.model.uci".cursor()
local proxy = ucic:get_first(name, 'server_subscribe', 'proxy', '0')
local switch = ucic:get_first(name, 'server_subscribe', 'switch', '1')
local allow_insecure = ucic:get_first(name, 'server_subscribe', 'allow_insecure', '0')
local subscribe_url = ucic:get_first(name, 'server_subscribe', 'subscribe_url', {})
local filter_words = ucic:get_first(name, 'server_subscribe', 'filter_words', '过期时间/剩余流量')
local save_words = ucic:get_first(name, 'server_subscribe', 'save_words', '')
local user_agent = ucic:get_first(name, 'server_subscribe', 'user_agent', 'v2rayN/9.99')
-- 读取 ss_type 设置
local ss_type = ucic:get_first(name, 'server_subscribe', 'ss_type', 'ss-rust')
-- 根据 ss_type 选择对应的程序
local ss_program = "sslocal"
if ss_type == "ss-rust" then
    ss_program = "sslocal"  -- Rust 版本使用 sslocal
elseif ss_type == "ss-libev" then
    ss_program = "ss-redir"  -- Libev 版本使用 ss-redir
end
local v2_ss = luci.sys.exec('type -t -p ' .. ss_program .. ' 2>/dev/null') ~= "" and "ss" or "v2ray"
local has_ss_type = luci.sys.exec('type -t -p ' .. ss_program .. ' 2>/dev/null') ~= "" and ss_type
local v2_tj = luci.sys.exec('type -t -p trojan') ~= "" and "trojan" or "v2ray"
local hy2_type = luci.sys.exec('type -t -p hysteria') ~= "" and "hysteria2"
local tuic_type = luci.sys.exec('type -t -p tuic-client') ~= "" and "tuic"
local log = function(...)
	print(os.date("%Y-%m-%d %H:%M:%S ") .. table.concat({...}, " "))
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
-- md5
local function md5(content)
	local stdout = luci.sys.exec('echo \"' .. urlEncode(content) .. '\" | md5sum | cut -d \" \" -f1')
	-- assert(nixio.errno() == 0)
	return trim(stdout)
end
-- base64
local function base64Decode(text)
	local raw = text
	if not text then
		return ''
	end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	if result then
		return result:gsub("%z", "")
	else
		return raw
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
-- 处理数据
local function processData(szType, content)
	local result = {type = szType, local_port = 1234, kcp_param = '--nocomp'}
	-- 检查JSON的格式如不完整丢弃
	if not (szType == "sip008" or szType == "ssd") then
		if not isCompleteJSON(content) then
			return nil
		end
	end

	if szType == "hysteria2" or szType == "hy2" then
		local url = URL.parse("http://" .. content)
		local params = url.query

		-- 调试输出所有参数
		-- log("Hysteria2 原始参数:")
		-- for k,v in pairs(params) do
		--	log(k.."="..v)
		-- end

		-- 如果 hy2 程序未安装则跳过订阅	
		if not hy2_type then
			return nil
		end

		result.alias = url.fragment and UrlDecode(url.fragment) or nil
		result.type = hy2_type
		result.server = url.host
		result.server_port = url.port or 443
		if params.protocol then
			result.flag_transport = "1"
			result.transport_protocol = params.protocol or "udp"
		end
		result.hy2_auth = url.user
		result.uplink_capacity = tonumber((params.upmbps or ""):match("^(%d+)")) or nil
		result.downlink_capacity = tonumber((params.downmbps or ""):match("^(%d+)")) or nil
		if params.mport then
			result.flag_port_hopping = "1"
			result.port_range = params.mport
		end
		if params.obfs and params.obfs ~= "none" then
			result.flag_obfs = "1"
			result.obfs_type = params.obfs
			result.salamander = params["obfs-password"] or params["obfs_password"]
		end
		if (params.sni and params.sni ~= "") or (params.alpn and params.alpn ~= "") then
			result.tls = "1"
			if params.sni then
				result.tls_host = params.sni
			end
			if params.alpn then
				local alpn = {}
				for v in params.alpn:gmatch("[^,;|%s]+") do
					table.insert(alpn, v)
				end
				result.tls_alpn = alpn
			end
		end
		if params.insecure == "1" then
			result.insecure = params.insecure
		end
		if params.pinSHA256 then
			result.pinsha256 = params.pinSHA256
		end
	elseif szType == 'ssr' then
		-- 去掉前后空白和#注释
		local link = trim(content:gsub("#.*$", ""))
		local dat = split(link, "/%?")
		local hostInfo = split(dat[1] or '', ':')

		result.type = 'ssr'
		result.server = hostInfo[1] or ''
		result.server_port = hostInfo[2] or ''
		result.protocol = hostInfo[3] or ''
		result.encrypt_method = hostInfo[4] or ''
		result.obfs = hostInfo[5] or ''
		result.password = base64Decode(hostInfo[6] or '')

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

		local group = base64Decode(params.group or '')
		local remarks = base64Decode(params.remarks or '')

		-- 拼接 alias
		local alias = ""
		if group ~= "" then
			alias = "[" .. group .. "] "
		end
		alias = alias .. remarks
		result.alias = alias
	elseif szType == "vmess" then
		-- 去掉前后空白和#注释
		local link = trim(content:gsub("#.*$", ""))

		-- 解析正常节点
		local success, info = pcall(jsonParse, link)
		if not success or type(info) ~= "table" then
			return nil
		end

		-- 基本信息
		result.type = 'v2ray'
		result.v2ray_protocol = 'vmess'
		result.server = info.add
		result.server_port = info.port
		result.alter_id = info.aid
		result.vmess_id = info.id
		result.alias = info.ps

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
			if params.extra and params.extra ~= "" then
				result.enable_xhttp_extra = "1"
				result.xhttp_extra = params.extra
			end
			-- 尝试解析 JSON 数据
			local success, Data = pcall(jsonParse, info.extra or "")
			if success and type(Data) == "table" then
				local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
					or (Data.downloadSettings and Data.downloadSettings.address)
				result.download_address = (address and address ~= "") and address or nil
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
			result.kcp_guise = info.type
			result.mtu = 1350
			result.tti = 50
			result.uplink_capacity = 5
			result.downlink_capacity = 20
			result.read_buffer_size = 2
			result.write_buffer_size = 2
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
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.fingerprint = info.fp
			if info.alpn and info.alpn ~= "" then
				local alpn = {}
				for v in info.alpn:gmatch("[^,]+") do
					table.insert(alpn, v)
				end
				result.tls_alpn = alpn
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
			-- 兼容 allowInsecure / allowlnsecure / skip-cert-verify
			if info.allowInsecure or info.allowlnsecure or info["skip-cert-verify"] then
				local insecure = info.allowInsecure or info.allowlnsecure or info["skip-cert-verify"]
				if insecure == true or insecure == "1" or insecure == "true" then
					result.insecure = "1"
				end
			end
		else
			result.tls = "0"
		end
		-- 其它可选安全字段
		if info.security then
			result.security = info.security
		end
	elseif szType == "ss" then
		local idx_sp = content:find("#") or 0
		local alias = ""
		if idx_sp > 0 then
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1):gsub("/%?", "?")
		end
		result.alias = UrlDecode(alias)

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

		if not params.type or params.type == "" then
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

			-- 如果 SS 程序未安装则跳过订阅	
			if not (v2_ss or has_ss_type) then
				return nil
			end

			-- 填充 result
			result.type = v2_ss
			result.has_ss_type = has_ss_type
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
			elseif has_ss_type and has_ss_type ~= "ss-libev" then
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
			else
				if params["shadow-tls"] then
					log("错误：ShadowSocks-libev 不支持使用 shadow-tls 插件")
					return nil, "ShadowSocks-libev 不支持使用 shadow-tls 插件"
				end
			end

			-- 检查加密方法是否受支持
			if not checkTabValue(encrypt_methods_ss)[method] then
				-- 1202 年了还不支持 SS AEAD 的屑机场
				-- log("不支持的SS加密方法:", method)
				result.server = nil
			end
		else
			local url = URL.parse("http://" .. info)
			local params = url.query

			v2_ss = "v2ray"
			result.type = v2_ss
			result.v2ray_protocol = "shadowsocks"
			result.server = url.host
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
				result.tls_alpn = params.alpn
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
			-- 检查 pqv 参数是否存在且非空
			if params.pqv and params.pqv ~= "" then
				result.enable_mldsa65verify = "1"
				result.reality_mldsa65verify = params.pqv
			end
			if result.transport == "ws" then
				result.ws_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
				result.ws_path = params.path and UrlDecode(params.path) or "/"
			elseif result.transport == "httpupgrade" then
				result.httpupgrade_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
				result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"
			elseif result.transport == "xhttp" or result.transport == "splithttp" then
				result.xhttp_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
				result.xhttp_mode = params.mode or "auto"
				result.xhttp_path = params.path and UrlDecode(params.path) or "/"
				-- 检查 extra 参数是否存在且非空
				if params.extra and params.extra ~= "" then
					result.enable_xhttp_extra = "1"
					result.xhttp_extra = params.extra
				end
				-- 尝试解析 JSON 数据
				local success, Data = pcall(jsonParse, params.extra or "")
				if success and type(Data) == "table" then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
						or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = address and address ~= "" and address or nil
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
				result.seed = params.seed
				result.mtu = 1350
				result.tti = 50
				result.uplink_capacity = 5
				result.downlink_capacity = 20
				result.read_buffer_size = 2
				result.write_buffer_size = 2
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
		end
	elseif szType == "sip008" then
		result.type = v2_ss
		result.v2ray_protocol = (v2_ss == "v2ray") and "shadowsocks" or nil
		result.has_ss_type = has_ss_type
		result.server = content.server
		result.server_port = content.server_port
		result.password = content.password
		result.encrypt_method_ss = content.method
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_opts
		result.alias = content.remarks
		if not checkTabValue(encrypt_methods_ss)[content.method] then
			result.server = nil
		end
	elseif szType == "ssd" then
		result.type = v2_ss
		result.v2ray_protocol = (v2_ss == "v2ray") and "shadowsocks" or nil
		result.has_ss_type = has_ss_type
		result.server = content.server
		result.server_port = content.port
		result.password = content.password
		result.encrypt_method_ss = content.method
		result.plugin_opts = content.plugin_options
		result.alias = "[" .. content.airport .. "] " .. content.remarks
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
		result.alias = UrlDecode(alias)

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
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.server_port = sp[#sp]
				result.server = sp[1]
			else
				result.server = host_port
			end

			-- 默认设置
			-- 按照官方的建议 默认验证ssl证书
			result.insecure = "0"
			result.tls = "1"

			-- 处理参数
			if params.alpn then
				-- 处理 alpn 参数
				result.tls_alpn = params.alpn
			end
			if params.peer or params.sni then
				-- 未指定peer（sni）默认使用remote addr
				result.tls_host = params.peer or params.sni
			end
			if params.allowInsecure then
				-- 处理 insecure 参数
				if params.allowinsecure == "1" or params.allowinsecure == "0" then
					result.insecure = params.allowInsecure
				else
					result.insecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
				end
			end
			if params.tfo then
				-- 处理 fast open 参数
				result.fast_open = params.tfo
			end
		else
			result.server_port = port
		end

		-- 如果 Tojan 程序未安装则跳过订阅	
		if not v2_tj or v2_tj == "" then
			return nil
		end

		if params.type and params.type ~= "" then
			v2_tj = "v2ray"
			result.type = v2_tj
			result.v2ray_protocol = "trojan"
			if v2_tj ~= "trojan" then
				if params.fp then
					-- 处理 fingerprint 参数
					result.fingerprint = params.fp
				end
				-- 处理 ech 参数
				if params.ech then
					result.enable_ech = "1"
					result.ech_config = params.ech
				end
				-- 处理传输协议
				result.transport = params.type or "raw" -- 默认传输协议为 raw
				if result.transport == "tcp" then
					result.transport = "raw"
				end
				if result.transport == "splithttp" then
					result.transport = "xhttp"
				end
				if result.transport == "ws" then
					result.ws_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
					result.ws_path = params.path and UrlDecode(params.path) or "/"
				elseif result.transport == "httpupgrade" then
					result.httpupgrade_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
					result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"
				elseif result.transport == "xhttp" or result.transport == "splithttp" then
					result.xhttp_host = (result.tls ~= "1") and (params.host and UrlDecode(params.host)) or nil
					result.xhttp_mode = params.mode or "auto"
					result.xhttp_path = params.path and UrlDecode(params.path) or "/"
					-- 检查 extra 参数是否存在且非空
					if params.extra and params.extra ~= "" then
						result.enable_xhttp_extra = "1"
						result.xhttp_extra = params.extra
					end
					-- 尝试解析 JSON 数据
					local success, Data = pcall(jsonParse, params.extra or "")
					if success and type(Data) == "table" then
						local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
							or (Data.downloadSettings and Data.downloadSettings.address)
						result.download_address = address and address ~= "" and address or nil
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
					result.seed = params.seed
					result.mtu = 1350
					result.tti = 50
					result.uplink_capacity = 5
					result.downlink_capacity = 20
					result.read_buffer_size = 2
					result.write_buffer_size = 2
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
			else
				result.type = v2_tj
			end
		end
	elseif szType == "vless" then
		local url = URL.parse("http://" .. content)
		local params = url.query

		result.alias = url.fragment and UrlDecode(url.fragment) or nil
		result.type = "v2ray"
		result.v2ray_protocol = "vless"
		result.server = url.host
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
		result.tls_flow = (security == "tls" or security == "reality") and params.flow or nil

		-- 处理 alpn 列表
		if params.alpn and params.alpn ~= "" then
			local alpn = {}
			for v in params.alpn:gmatch("[^,;|%s]+") do
				table.insert(alpn, v)
			end
			result.tls_alpn = alpn
		end

		-- Reality 参数
		if security == "reality" then
			result.reality_publickey = params.pbk and UrlDecode(params.pbk) or nil
			result.reality_shortid = params.sid
			result.reality_spiderx = params.spx and UrlDecode(params.spx) or nil

			-- PQ 验证参数
			if params.pqv and params.pqv ~= "" then
				result.enable_mldsa65verify = "1"
				result.reality_mldsa65verify = params.pqv
			end
		end

		-- ECH 参数（TLS 才有）
		if security == "tls" and params.ech and params.ech ~= "" then
			result.enable_ech = "1"
			result.ech_config = params.ech
		end

		-- 各种传输类型
		if result.transport == "ws" then
			result.ws_host = (result.tls ~= "1" and result.reality ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.ws_path = params.path and UrlDecode(params.path) or "/"

		elseif result.transport == "httpupgrade" then
			result.httpupgrade_host = (result.tls ~= "1" and result.reality ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.httpupgrade_path = params.path and UrlDecode(params.path) or "/"

		elseif result.transport == "xhttp" then
			result.xhttp_host = (result.tls ~= "1" and result.reality ~= "1") and (params.host and UrlDecode(params.host)) or nil
			result.xhttp_mode = params.mode or "auto"
			result.xhttp_path = params.path and UrlDecode(params.path) or "/"
			if params.extra and params.extra ~= "" then
				result.enable_xhttp_extra = "1"
				result.xhttp_extra = params.extra
			end
			local success, Data = pcall(jsonParse, params.extra or "")
			if success and type(Data) == "table" then
				local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
					or (Data.downloadSettings and Data.downloadSettings.address)
				result.download_address = address and address ~= "" and address or nil
			else
				result.download_address = nil
			end

		elseif result.transport == "h2" then
			result.h2_host = params.host and UrlDecode(params.host) or nil
			result.h2_path = params.path and UrlDecode(params.path) or nil

		elseif result.transport == "kcp" then
			result.kcp_guise = params.headerType or "none"
			result.seed = params.seed
			result.mtu = 1350
			result.tti = 50
			result.uplink_capacity = 5
			result.downlink_capacity = 20
			result.read_buffer_size = 2
			result.write_buffer_size = 2

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
		-- 提取别名（如果存在）
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.alias = UrlDecode(alias)

		-- 分离和提取 uuid 和 password
		local Info = content
		if Info:find("@") then
			local contents = split(Info, "@")
			if contents[1]:find(":") then
				local userinfo = split(contents[1], ":")
				result.tuic_uuid = UrlDecode(userinfo[1])
				result.tuic_passwd = UrlDecode(userinfo[2])
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
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.server_port = sp[#sp]
			result.server = sp[1]
		else
			result.server = host_port
		end

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
			result.tuic_alpn = alpn
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

		-- 处理 insecure 参数
		if params.allowInsecure then
			if params.allowinsecure == "1" or params.allowinsecure == "0" then
				result.insecure = params.allowInsecure
		else
				result.insecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
			end
		end
	end
	if not result.alias then
		if result.server and result.server_port then
			result.alias = result.server .. ':' .. result.server_port
		else
			result.alias = "NULL"
		end
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
local function curl(url)
	-- 清理 URL 中的隐藏字符
	url = url:gsub("%s+$", ""):gsub("^%s+", ""):gsub("%z", "")

	-- 构建curl命令（确保 user_agent 为空时不添加 -A 参数）
	local cmd = string.format(
		'curl -sSL --connect-timeout 20 --max-time 30 --retry 3 %s --insecure --location "%s"',
		user_agent ~= "" and ('-A "' .. user_agent .. '"') or "",  -- 添加 or "" 处理 nil 情况
		url:gsub('["$`\\]', '\\%0')  -- 安全转义
	)

	local stdout = luci.sys.exec(cmd)
	stdout = trim(stdout)
	local md5 = md5_string(stdout)
	return stdout, md5
end

local function check_filer(result)
	do
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
end

-- 加载订阅未变化的节点用于防止被误删
local function loadOldNodes(groupHash)
	local nodes = {}
	cache[groupHash] = {}
	nodeResult[#nodeResult + 1] = nodes
	local index = #nodeResult

	ucic:foreach(name, uciType, function(s)
		if s.grouphashkey == groupHash and s.hashkey then
			local section = setmetatable({}, {__index = s})
			nodes[s.hashkey] = section
			cache[groupHash][s.hashkey] = section
		end
	end)
end

local execute = function()
	-- exec
	do
		--local updated = false 
		local service_stopped = false
		for k, url in ipairs(subscribe_url) do
			local raw, new_md5 = curl(url)
			log("raw 长度: "..#raw)
			local groupHash = md5(url)
			local old_md5 = read_old_md5(groupHash)

			log("处理订阅: " .. url)
			log("groupHash: " .. groupHash)
			log("old_md5: " .. tostring(old_md5))
			log("new_md5: " .. tostring(new_md5))

			if #raw > 0 then
				if old_md5 and new_md5 == old_md5 then
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
					updated = true
					-- 保存更新后的 MD5 值到以 groupHash 为标识的临时文件中，用于下次订阅更新时进行对比
					write_new_md5(groupHash, new_md5)

					-- 暂停服务（仅当 MD5 有变化时才执行）
					if proxy == '0' and not service_stopped then
						log('服务正在暂停')
						luci.sys.init.stop(name)
						service_stopped = true
					end

					cache[groupHash] = {}
					tinsert(nodeResult, {})
					local index = #nodeResult
					local nodes, szType

					-- SSD 似乎是这种格式 ssd:// 开头的
					if raw:find('ssd://') then
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
					for _, v in ipairs(nodes) do
						if v and not string.match(v, "^%s*$") then
							xpcall(function()
								local result
								if szType then
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
										if dat[1] == 'ss' or dat[1] == 'trojan' or dat[1] == 'tuic' then
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
									-- 中文做地址的 也没有人拿中文域名搞，就算中文域也有Puny Code SB 机场
									if not result.server or not result.server_port
										or result.server == "127.0.0.1"
										or result.alias == "NULL"
										or check_filer(result)
										or result.server:match("[^0-9a-zA-Z%-_%.%s]")
										or cache[groupHash][result.hashkey]
									then
										log('丢弃无效节点: ' .. result.alias)
									else
										-- log('成功解析: ' .. result.type ..' 节点, ' .. result.alias)
										result.grouphashkey = groupHash
										tinsert(nodeResult[index], result)
										cache[groupHash][result.hashkey] = nodeResult[index][#nodeResult[index]]
									end
								end
							end, function(err)
								log(string.format("解析节点出错: %s\n原始数据: %s", tostring(err), tostring(v)))
							end)	
						end
					end
					log('成功解析节点数量: ' .. #nodes)
				end
			else
				log(url .. ': 获取内容为空')
			end
		end
	end
	-- 输出日志并判断是否需要进行 diff
	if not updated then
		log("订阅未变化，无需更新节点信息。")
		log('保留手动添加的节点。')
		return
	end
	-- diff
	do
		if next(nodeResult) == nil then
			log("更新失败，没有可用的节点信息")
			if proxy == '0' then
				luci.sys.init.start(name)
				log('订阅失败, 恢复服务')
			end
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
					ucic:tset(name, old['.name'], dat)
					-- 标记一下
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
		for k, v in ipairs(nodeResult) do
			for kk, vv in ipairs(v) do
				if not vv._ignore then
					local section = ucic:add(name, uciType)
					ucic:tset(name, section, vv)
					ucic:set(name, section, "switch_enable", switch)
					add = add + 1
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
end

if subscribe_url and #subscribe_url > 0 then
	xpcall(execute, function(e)
		log(e)
		log(debug.traceback())
		log('发生错误, 正在恢复服务')
		local firstServer = ucic:get_first(name, uciType)
		if firstServer then
			luci.sys.call("/etc/init.d/" .. name .. " restart > /dev/null 2>&1 &") -- 不加&的话日志会出现的更早
			log('重启服务成功')
		else
			luci.sys.call("/etc/init.d/" .. name .. " stop > /dev/null 2>&1 &") -- 不加&的话日志会出现的更早
			log('停止服务成功')
		end
	end)
end
