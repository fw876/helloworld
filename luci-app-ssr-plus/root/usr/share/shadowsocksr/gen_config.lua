#!/usr/bin/lua

require "luci.sys"
local ucursor = require "luci.model.uci".cursor()
local json = require "luci.jsonc"

-- An omitted value reaches us either as a missing argument or as an empty
-- string, depending on whether the caller quoted the expansion. Empty strings
-- are truthy in Lua, so "arg[n] or default" alone does not cover both.
local function argv(n, default)
	local value = arg[n]
	if value == nil or value == "" then
		return default
	end
	return value
end

local server_section = arg[1]
local proto          = argv(2, "tcp")
local local_port     = argv(3, "0")
local socks_port     = argv(4, "0")

local chain          = argv(5, "0")

-- trim
local function trim(text)
	if not text or text == "" then
		return ""
	end
	return (text:gsub("^%s*(.-)%s*$", "%1"))
end

-- 辅助函数：拆分字符串（若 luci.util 未加载则定义）
local function split(str, pat)
	local t = {}
	local last = 1
	while true do
		local pos = str:find(pat, last, true)
		if not pos then break end
		table.insert(t, str:sub(last, pos - 1))
		last = pos + 1
	end
	table.insert(t, str:sub(last))
	return t
end

local chain_local_port = split(chain, "/")[2] or "0"

local server = ucursor:get_all("shadowsocksr", server_section)
local socks_server = ucursor:get_all("shadowsocksr", "@socks5_proxy[0]") or {}
local xray_fragment = ucursor:get_all("shadowsocksr", "@global_xray_fragment[0]") or {}
local xray_noise = ucursor:get_all("shadowsocksr", "@xray_noise_packets[0]") or {}
local default_node_local_port = ucursor:get_first("shadowsocksr", "global", "default_node_local_port", "1234")
local dns_mode = ucursor:get_first("shadowsocksr", "global", "pdnsd_enable", "0")
local dns_ipv4_only = ucursor:get_first("shadowsocksr", "global", "filter_aaaa")
if not dns_ipv4_only or dns_ipv4_only == "" then
	dns_ipv4_only = ucursor:get_first("shadowsocksr", "global", "mosdns_ipv6", "1")
end
local builtin_dns_server = ucursor:get_first("shadowsocksr", "global", "tunnel_forward", "8.8.4.4:53")
local outbound_settings = nil
local xray_version = nil
local xray_version_val = 0
local xray_builtin_dns = nil

local node_id = server_section
local remarks = server.alias or ""
local b64decode = nixio.bin.b64decode
local b64encode = nixio.bin.b64encode
local effective_node_local_port = tonumber(server.local_port) or tonumber(default_node_local_port) or 1234

if server.type == "ss-rust" then
	server.type = "ss"
end

local function parse_realm_uri(uri)
	uri = trim(uri)
	if uri == "" then return nil end
	-- realm[+http]://token@server/realm_id?query
	local scheme = (uri:match("^realm%+http://") and "realm+http") or (uri:match("^realm://") and "realm")
	if not scheme then return nil end
	uri = uri:gsub("^realm%+http://", ""):gsub("^realm://", "")
	local token, server_url, realm_id, query = uri:match("^([^@]+)@([^/]+)/([^?]*)%??(.*)$")
	if not token or not server_url or not realm_id then return nil end
	realm_id = realm_id:gsub("/+$", "")
	local address, port = server_url:match("^%[([^%]]+)%]:(%d+)$") --ipv6:port
	if not address then
		address, port = server_url:match("^([^:]+):(%d+)$") --ipv4[domain]:port
	end
	address = address or server_url:match("^%[([^%]]+)%]$") or server_url
	port = tonumber(port) or (scheme == "realm+http" and 80 or 443)
	local realm = {
		scheme = scheme,
		token = token,
		server_url = server_url,
		address = address,
		port = port,
		realm_id = realm_id
	}
	-- 解析 query 中的 stun=
	local stun_servers
	for v in (query or ""):gmatch("[Ss][Tt][Uu][Nn]=([^&]+)") do
		stun_servers = stun_servers or {}
		stun_servers[#stun_servers + 1] = v
	end
	realm.stun_servers = stun_servers
	return realm
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

-- Hex 编码
local function hexEncode(text)
	if not text or text == "" then
		return ''
	end
	local hex = ''
	for i = 1, #text do
		local byte = string.byte(text, i)
		hex = hex .. string.format('%02X', byte)
	end
	return hex
end

local function cleanEmptyTables(t)
	if type(t) ~= "table" then return nil end
	for k, v in pairs(t) do
		if type(v) == "table" then
			t[k] = cleanEmptyTables(v)
		end
	end
	return next(t) and t or nil
end

local function format_host(host)
	host = tostring(host or "")
	if host ~= "" and host:find(":", 1, true) and not host:match("^%[.*%]$") then
		return "[" .. host .. "]"
	end
	return host
end

local function format_host_port(host, port)
	host = format_host(host)
	if port == nil or port == "" then
		return host
	end
	return host .. ":" .. tostring(port)
end

-- 确保正确判断程序是否存在
local function is_finded(e)
	return luci.sys.exec(string.format('type -t -p "%s" -p "/usr/libexec/%s" 2>/dev/null', e, e)) ~= ""
end

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

function vmess_vless()
	outbound_settings = {
		vnext = {
			{
				address = server.server,
				port = tonumber(server.server_port),
				users = {
					{
						id = server.vmess_id,
						alterId = (server.v2ray_protocol == "vmess" or not server.v2ray_protocol) and tonumber(server.alter_id) or nil,
						security = (server.v2ray_protocol == "vmess" or not server.v2ray_protocol) and server.security or nil,
						testpre = (server.v2ray_protocol == "vless" or not server.v2ray_protocol) and tonumber(server.preconns) or nil,
						encryption = (server.v2ray_protocol == "vless" or (not server.v2ray_protocol and server.vless_encryption)) and (server.vless_encryption or "none") or nil,
						flow = (server.v2ray_protocol == "vless" and (server.xtls == "1" or server.tls == "1" or server.reality == "1"
								or (server.vless_encryption and server.vless_encryption ~= "" and server.vless_encryption ~= "none")) and (
								server.transport == "raw" or server.transport == "tcp" or server.transport == "xhttp" or server.transport == "splithttp") and (
								server.tls_flow and server.tls_flow ~= "none")) and server.tls_flow or nil
					}
				}
			}
		}
	}
end
function trojan_shadowsocks()
	outbound_settings = {
		servers = {
			{
				address = server.server,
				port = tonumber(server.server_port),
				password = server.password,
				method = ((server.v2ray_protocol == "shadowsocks") and server.encrypt_method_ss) or nil,
				uot = (server.v2ray_protocol == "shadowsocks") and (server.uot == '1') or nil,
				ivCheck = (server.v2ray_protocol == "shadowsocks") and (server.ivCheck == '1') or nil,
			}
		}
	}
end
function socks_http()
	outbound_settings = {
		version = server.socks_ver or nil,
		servers = {
			{
				address = server.server,
				port = tonumber(server.server_port),
				users = (server.auth_enable == "1") and {
					{
						user = server.username,
						pass = server.password
					}
				} or nil
			}
		}
	}
end
function wireguard()
	-- 处理 reserved 字段，支持逗号分隔的数字或 Base64 编码
	local reserved = nil
	if server.reserved then
		local all_bytes = {}
		local reserved_values = server.reserved

		-- 确保是 table 类型
		if type(reserved_values) ~= "table" then
			reserved_values = {reserved_values}
		end

		for _, reserved_str in ipairs(reserved_values) do
			if type(reserved_str) == "string" then
				if not reserved_str:match("[^%d,]+") then
					-- 数字和逗号格式
					reserved_str:gsub("%d+", function(b)
						all_bytes[#all_bytes + 1] = tonumber(b)
					end)
				else
					-- Base64 格式
					local result = base64Decode(reserved_str)
					if result then
						for i = 1, #result do
							all_bytes[#all_bytes + 1] = result:byte(i)
						end
					end
				end
			end
		end
		reserved = #all_bytes > 0 and all_bytes or nil
	end

	outbound_settings = {
		secretKey = server.private_key,
		address = server.local_addresses,
		peers = {
			{
				publicKey = server.peer_pubkey,
				preSharedKey = server.preshared_key,
				endpoint = format_host_port(server.server, server.server_port),
				keepAlive = tonumber(server.keepaliveperiod),
				allowedIPs = (server.allowedips) or nil,
			}
		},
		noKernelTun = (server.kernelmode == "1") and true or false,
		reserved = reserved,
		mtu = tonumber(server.mtu)
	}
	if server.finalmask and server.finalmask ~= "" then
		local ok, fm = pcall(json.parse, base64Decode(server.finalmask))
		if ok and type(fm) == "table" then
			outbound_settings.streamSettings = outbound_settings.streamSettings or {}
			outbound_settings.streamSettings.finalmask = fm
		end
	end
end
function xray_hysteria2()
	outbound_settings = {
		version = (server.v2ray_protocol == "hysteria2") and 2 or nil,
		address = server.server,
		port = tonumber(server.server_port)
	}

	-- Realm 支持：使用 Realm 服务器地址覆盖默认地址
	if server.v2ray_protocol == "hysteria2" and server.hysteria2_realms then
		local realm = parse_realm_uri(server.hysteria2_realm_url)
		if realm then
			outbound_settings.address = realm.address
			outbound_settings.port = realm.port
		end
	end
end
local outbound = {}
function outbound:new(o)
	o = o or {}
	setmetatable(o, self)
	self.__index = self
	return o
end
function outbound:handleIndex(index)
	local switch = {
		vmess = function()
			vmess_vless()
		end,
		vless = function()
			vmess_vless()
		end,
		trojan = function()
			trojan_shadowsocks()
		end,
		shadowsocks = function()
			trojan_shadowsocks()
		end,
		socks = function()
			socks_http()
		end,
		http = function()
			socks_http()
		end,
		wireguard = function()
			wireguard()
		end,
		hysteria2 = function()
			xray_hysteria2()
		end
	}
	if switch[index] then
		switch[index]()
	end
end
local settings = outbound:new()
settings:handleIndex(server.v2ray_protocol)
local Xray = {
	log = {
		-- error = "/var/ssrplus.log",
		-- loglevel = "debug",
		-- dnsLog = true,
		-- access = "/var/log/ssrplus-access.log",
		-- error = "/var/log/ssrplus-error.log"
		loglevel = "warning"
	},

	-- 初始化 inbounds 表
	inbounds = {},

	-- 初始化 outbounds 表
	outbounds = {},
}

if server.type == "v2ray" and dns_mode == "7" and os.getenv("SSR_SWITCH_PROBE") ~= "1" then
	local dns_host = builtin_dns_server:match("^([^:]+)") or "8.8.4.4"
	local dns_port = tonumber(builtin_dns_server:match(":(%d+)$")) or 53

	Xray.dns = {
		queryStrategy = (dns_ipv4_only == "1") and "UseIPv4" or "UseIP",
		servers = {
			string.format("tcp://%s:%d", dns_host, dns_port)
		}
	}

	table.insert(Xray.inbounds, {
		listen = "127.0.0.1",
		port = 5335,
		protocol = "dokodemo-door",
		settings = {
			address = dns_host,
			port = dns_port,
			network = "tcp,udp"
		},
		tag = "builtin-dns-in"
	})

	xray_builtin_dns = {
		address = dns_host,
		port = dns_port
	}
end
	-- 传入连接
	-- 添加 dokodemo-door 配置，如果 local_port 不为 0
if local_port ~= "0" then
    table.insert(Xray.inbounds, {
			-- listening
			port = tonumber(local_port),
			protocol = "dokodemo-door",
			settings = {network = proto, followRedirect = true},
			sniffing = {
				enabled = true,
				destOverride = {"http", "tls", "quic"},
				metadataOnly = false,
				domainsExcluded = {
					"courier.push.apple.com",
					"rbsxbxp-mim.vivox.com",
					"rbsxbxp.www.vivox.com",
					"rbsxbxp-ws.vivox.com",
					"rbspsxp.www.vivox.com",
					"rbspsxp-mim.vivox.com",
					"rbspsxp-ws.vivox.com",
					"rbswxp.www.vivox.com",
					"rbswxp-mim.vivox.com",
					"disp-rbspsp-5-1.vivox.com",
					"disp-rbsxbp-5-1.vivox.com",
					"proxy.rbsxbp.vivox.com",
					"proxy.rbspsp.vivox.com",
					"proxy.rbswp.vivox.com",
					"rbswp.vivox.com",
					"rbsxbp.vivox.com",
					"rbspsp.vivox.com",
					"rbspsp.www.vivox.com",
					"rbswp.www.vivox.com",
					"rbsxbp.www.vivox.com",
					"rbsxbxp.vivox.com",
					"rbspsxp.vivox.com",
					"rbswxp.vivox.com",
					"Mijia Cloud",
					"dlg.io.mi.com"
				}
			}
    })
end

	-- 开启 socks 代理
	-- 检查是否启用 socks 代理
if proto and proto:find("tcp") and socks_port ~= "0" then
	local auth = (socks_server.socks5_auth and socks_server.socks5_auth ~= "noauth")
		and {{
			user = socks_server.socks5_user,
			pass = socks_server.socks5_pass
		}} or nil

	table.insert(Xray.inbounds, {
		-- socks
		protocol = "socks",
		port = tonumber(socks_port),
		settings = {
			auth = socks_server.socks5_auth or "noauth",
			udp = true,
			mixed = socks_server.socks5_mixed == "1" or nil,
			accounts = (xray_version_val <= 260503) and auth or nil,
			users = (xray_version_val > 260503) and auth or nil
		}
	})
end

-- 传出连接
Xray.outbounds = {
	{
		protocol = (server.v2ray_protocol == "hysteria2") and "hysteria" or server.v2ray_protocol,
		settings = outbound_settings,
		tag = (remarks ~= nil and remarks ~= "") and (node_id .. ":" .. remarks) or node_id,
		-- 底层传输配置
		streamSettings = (server.v2ray_protocol ~= "wireguard") and {
			[(xray_version_val >= 260711) and "method" or "network"] = (server.v2ray_protocol == "hysteria2") and "hysteria" or (server.transport or "raw"),
			security = (server.xtls == '1') and "xtls" or (server.tls == '1') and "tls" or (server.reality == '1') and "reality" or nil,
			tlsSettings = (server.tls == '1') and {
				-- tls
				alpn = (server.tls_alpn and server.tls_alpn ~= "") and (function()
					local alpn = {}
					string.gsub(server.tls_alpn, '[^,]+', function(w)
						table.insert(alpn, w)
					end)
					if #alpn > 0 then
						return alpn
					else
						return nil
					end
				end)() or nil,
				fingerprint = server.fingerprint,
				allowInsecure = (function()
					if server.tls_CertSha and server.tls_CertSha ~= "" then return nil end
					if os.date("%Y.%m.%d") < "2026.06.01" then
						return server.insecure == "1"
					end
					return nil
				end)(),
				serverName = server.tls_host,
				certificates = server.certificate and {
					usage = "verify",
					certificateFile = server.certpath
				} or nil,
				pinnedPeerCertSha256 = (function()
					if xray_version_val < 260131 then return nil end
					if not server.tls_CertSha then return "" end
					return server.tls_CertSha
				end)(),
				verifyPeerCertByName = (function()
					if xray_version_val < 260131 then return nil end
					if not server.tls_CertByName then return "" end
					return server.tls_CertByName
				end)(),
				echConfigList = (server.enable_ech == "1") and server.ech_config or nil,
				echForceQuery = (server.enable_ech == "1") and (server.ech_ForceQuery or "full") or nil
			} or nil,
			xtlsSettings = (server.xtls == '1') and server.tls_host and {
				-- xtls
				allowInsecure = (server.insecure == "1") and true or nil,
				serverName = server.tls_host,
				minVersion = "1.3"
			} or nil,
			realitySettings = (server.reality == '1') and {
				publicKey = server.reality_publickey,
				shortId = server.reality_shortid or "",
				spiderX = server.reality_spiderx or "",
				fingerprint = server.fingerprint,
				mldsa65Verify = (server.enable_mldsa65verify == '1') and server.reality_mldsa65verify or nil,
				serverName = server.tls_host
			} or nil,
			rawSettings = ((server.transport == "raw" or server.transport == "tcp")
				and (server.tcp_guise and server.tcp_guise ~= "none")) and {
				-- tcp
				header = {
					type = server.tcp_guise,
					request = (server.tcp_guise == "http") and {
						path = server.http_path and (function()
							local t, r = server.http_path, {}
							if type(t) == "string" then t = {t} end
							for _, v in ipairs(t) do
								r[#r + 1] = (v == "" and "/" or v)
							end
							return r
						end)() or {"/"},
						headers = (server.http_path or server.user_agent) and {
							Host = (type(server.http_host) == "string") and {server.http_host} or server.http_host,
							["User-Agent"] = server.user_agent and {server.user_agent} or nil
						} or nil
					} or nil
				}
			} or nil,
			kcpSettings = (server.transport == "kcp") and {
				-- kcp
				mtu =  (server.mtu and server.mtu ~= "") and tonumber(server.mtu) or 1350,
				tti = 50,
				uplinkCapacity = 12,
				downlinkCapacity = 100,
				CwndMultiplier = 1,
				MaxSendingWindow = 2 * 1024 * 1024
			} or nil,
			wsSettings = (server.transport == "ws") and (server.ws_path or server.ws_host or server.tls_host) and {
				-- ws
				host = server.ws_host or server.tls_host or nil,
				path = server.ws_path or "/",
				headers = server.user_agent and {
					["User-Agent"] = server.user_agent
				} or nil,
				maxEarlyData = tonumber(server.ws_ed) or nil,
				earlyDataHeaderName = server.ws_ed_header or nil,
				heartbeatPeriod = tonumber(server.ws_heartbeatPeriod) or nil
			} or nil,
			httpupgradeSettings = (server.transport == "httpupgrade") and {
				-- httpupgrade
				host = (server.httpupgrade_host or server.tls_host) or nil,
				path = server.httpupgrade_path or "",
				headers =  server.user_agent and {
					["User-Agent"] = server.user_agent
				} or nil
			} or nil,
			xhttpSettings = (server.transport == "xhttp" or server.transport == "splithttp") and {
				-- xhttp
				mode = server.xhttp_mode or "auto",
				host = (server.xhttp_host or server.tls_host) or nil,
				path = server.xhttp_path or "/",
				extra = (function()
					local extra = {}
					-- 解析 xhttp_extra（Base64 编码的 JSON）
					if (server.enable_xhttp_extra == "1" and server.xhttp_extra) then
						local ok, parsed = pcall(json.parse, base64Decode(server.xhttp_extra))
						if ok and type(parsed) == "table" then
							extra = parsed.extra or parsed   -- 取 "extra" 节，若无则整个 parsed
						end
					end
					-- 处理 User-Agent
					if server.user_agent and server.user_agent ~= "" then
						extra.headers = extra.headers or {}
						if not extra.headers["User-Agent"] and not extra.headers["user-agent"] then
							extra.headers["User-Agent"] = server.user_agent
						end
					end
					-- 递归清理空表（如空 headers 会被删除）
					return cleanEmptyTables(extra)
				end)()
			} or nil,
			httpSettings = (server.transport == "h2") and {
				-- h2
				path = server.h2_path or "",
				host = {server.h2_host} or nil,
				read_idle_timeout = tonumber(server.read_idle_timeout) or nil,
				health_check_timeout = tonumber(server.health_check_timeout) or nil
			} or nil,
			quicSettings = (server.transport == "quic") and {
				-- quic
				security = server.quic_security,
				key = server.quic_key,
				header = {type = server.quic_guise}
			} or nil,
			grpcSettings = (server.transport == "grpc") and {
				-- grpc
				serviceName = (server.serviceName and server.serviceName ~= "") and server.serviceName or nil,
				multiMode = (server.grpc_mode == "multi") and true or nil,
				idle_timeout = server.idle_timeout and (tonumber(server.idle_timeout) < 10 and 10 or tonumber(server.idle_timeout)) or nil,
				health_check_timeout = server.health_check_timeout and tonumber(server.health_check_timeout) or nil,
				permit_without_stream = (server.permit_without_stream == "1") and true or nil,
				initial_windows_size = server.initial_windows_size and tonumber(server.initial_windows_size) or nil,
				user_agent = server.user_agent
			} or nil,
			hysteriaSettings = (server.v2ray_protocol == "hysteria2") and {
				-- hysteria2
				version = 2,
				auth = server.hy2_auth
			} or nil,
			finalmask = (function()
				local finalmask = {}
				local PT = server.v2ray_protocol
				local TP = server.transport
				if TP == "kcp" then
					local map = {none = "none", srtp = "header-srtp", utp = "header-utp", ["wechat-video"] = "header-wechat",
						dtls = "header-dtls", wireguard = "header-wireguard", dns = "header-dns"}
					local udp = {}
					if server.kcp_guise and server.kcp_guise ~= "none" then
						local g = { type = map[server.kcp_guise] }
						if server.kcp_guise == "dns" and server.kcp_domain and server.kcp_domain ~= "" then
							g.settings = { domain = server.kcp_domain }
						end
						udp[#udp+1] = g
					end
					local c = { type = (server.seed and server.seed ~= "") and "mkcp-aes128gcm" or "mkcp-original" }
					if server.seed and server.seed ~= "" then
						c.settings = { password = server.seed }
					end
					udp[#udp+1] = c
					finalmask.udp = udp
				elseif PT == "hysteria2" then
					local udp = {}
					if (server.flag_obfs == "1" and (server.obfs_type and server.obfs_type ~= "")) then
						local o = {
							type = "salamander",
							settings = server.salamander and {
								password = server.salamander
							} or nil
						}
						if server.obfs_type == "gecko" then
							local min = tonumber(server.obfs_MinPacketSize) or 512
							local max = tonumber(server.obfs_MaxPacketSize) or 1200
							if min <= 0 or min > max or max > 2048 then
								min = 512
								max = 1200
							end
							o.settings.packetSize = min .. "-" .. max
						end
						udp[#udp+1] = o
					end
					if server.hysteria2_realms then
						local realm = parse_realm_uri(server.hysteria2_realm_url)
						local url, stun
						if realm then
							url = realm.scheme .. "://" .. realm.token .. "@" .. realm.server_url .. "/" .. realm.realm_id
							stun = realm.stun_servers or server.hysteria2_realm_stun
						end
						local r = {
							type = "realm",
							settings = {
								url = url,
								stunServers = stun
							}
						}
						udp[#udp+1] = r
					end
					finalmask.udp = udp
					local up = tonumber(server.uplink_capacity) or 0
					local down = tonumber(server.downlink_capacity) or 0
					finalmask.quicParams = {
						congestion = server.hy2_tcpcongestion or nil,
						brutalUp = up > 0 and (up .. "mbps") or nil,
						brutalDown = down > 0 and (down .. "mbps") or nil,
						udpHop = (server.flag_port_hopping == "1") and {
							ports = string.gsub(server.port_range, ":", "-"),
							interval = (function(v)
								if not v then return 30 end
								if v:find("-", 1, true) then
									local min, max = v:match("^(%d+)%-(%d+)$")
									min = tonumber(min)
									max = tonumber(max)
									if min and max then
										min = (min >= 5) and min or 5
										max = (max >= min) and max or min
										return min .. "-" .. max
									end
									return 30
								end
								v = tonumber((v or "30"):match("^%d+"))
								return (v and v >= 5) and v or 30
							end)(server.hopinterval)
						} or nil,
						initStreamReceiveWindow = (server.flag_quicparam == "1" and server.initstreamreceivewindow) and tonumber(server.initstreamreceivewindow) or nil,
						maxStreamReceiveWindow = (server.flag_quicparam == "1" and server.maxstreamreceivewindow) and tonumber(server.maxstreamreceivewindow) or nil,
						initConnectionReceiveWindow = (server.flag_quicparam == "1" and server.initconnreceivewindow) and tonumber(server.initconnreceivewindow) or nil,
						maxConnectionReceiveWindow = (server.flag_quicparam == "1" and server.maxconnreceivewindow) and tonumber(server.maxconnreceivewindow) or nil,
						maxIdleTimeout = (server.flag_quicparam == "1" and (function(t)
							t = tonumber(tostring(t or "30"):match("^%d+"))
							return (t and t >= 4 and t <= 120) and t or 30
						end)(server.maxidletimeout) or 30),
						keepAlivePeriod = (server.flag_quicparam == "1" and server.keepaliveperiod) and tonumber(server.keepaliveperiod) or nil,
						disablePathMTUDiscovery = (server.flag_quicparam == "1" and tostring(server.disablepathmtudiscovery) == "1") and true or nil
					}
				end
				if xray_fragment.fragment == "1" and ({raw=1, ws=1, httpupgrade=1, grpc=1, xhttp=1})[TP] then
					local n_packets = xray_fragment.fragment_packets
					local n_length = xray_fragment.fragment_length
					local n_delay = xray_fragment.fragment_delay
					local n_maxsplit = xray_fragment.fragment_maxSplit
					--local domainstr = xray_noise.domainStrategy
					finalmask.tcp = finalmask.tcp or {}
					-- 构建 fragment settings
					local fragment_settings = {
						packets = (n_packets and n_packets ~= "") and n_packets or nil,
						maxSplit = (n_maxsplit and n_maxsplit ~= "") and n_maxsplit or nil
					}
					-- 根据 Xray 版本决定使用旧格式还是新格式
					if xray_version_val <= 260601 then
						-- 旧版本：使用 length 和 delay（单个值）
						if n_length and n_length ~= "" then
							fragment_settings.length = n_length
						end
						if n_delay and n_delay ~= "" then
							if type(n_delay) == "string" and n_delay:find("-", 1, true) then
								fragment_settings.delay = n_delay
							else
								fragment_settings.delay = tonumber(n_delay)
							end
						end
					else
						-- 新版本：使用 lengths 和 delays（数组）
						-- 将逗号分隔的字符串拆分为数组
						local function split_to_array(str)
							if not str or str == "" then return nil end
								local result = {}
								local trimmed = trim(str)
								if trimmed and trimmed ~= "" then
									trimmed:gsub("[^,]+", function(w)
									w = w:gsub("%s+", "")
									if w ~= "" then
										result[#result + 1] = w
									end
								end)
							end
							return #result > 0 and result or nil
						end
						local lengths_array = split_to_array(n_length)
						if lengths_array then
							fragment_settings.lengths = lengths_array
						end
						local delays_array = split_to_array(n_delay)
						if delays_array then
							fragment_settings.delays = delays_array
						end
					end
					finalmask.tcp[#finalmask.tcp + 1] = {
						type = "fragment",
						settings = fragment_settings
					}
				end
				if xray_fragment.noise == "1" and (TP == "kcp" or (TP == "xhttp" and (server.tls_alpn == "h3" or server.tls_alpn == "h3,h2"))) then 
					if xray_noise.enabled == "1" then
						local n_type = xray_noise.type
						local n_delay = xray_noise.delay
						local n_packet = xray_noise.packet
						finalmask.udp = finalmask.udp or {}
						finalmask.udp[#finalmask.udp + 1] = {
							type = "noise",
							settings = {
								reset = 0,
								noise = {
									{
										rand = (n_type == "rand") and (n_packet and (type(n_packet) == "string" and (n_packet:find("-")) and n_packet or tonumber(n_packet))) or nil,
										type = (type(n_type) == "string" and n_type ~= "rand") and n_type or nil,
										packet = (n_type ~= "rand") and ((n_packet and type(n_packet) == "string") and ((n_type == "hex" and hexEncode(n_packet)) or (n_type == "base64" and base64Encode(n_packet))) or n_packet) or nil,
										delay = (type(n_delay) == "string" and string.find(n_delay, "-")) and n_delay or (n_delay and tonumber(n_delay))
									}
								}
							}
						}
					end
				end
				if server.finalmask and server.finalmask ~= "" then
					local ok, fm = pcall(json.parse, base64Decode(server.finalmask))
					if ok and type(fm) == "table" then
						finalmask = fm
					end
				end
				return cleanEmptyTables(finalmask)
			end)(),
			sockopt = {
				mark = 255,
				tcpFastOpen = (function()
					if server.transport == "xhttp" then
						return (server.fast_open == "1") and true or false
					elseif server.v2ray_protocol == "hysteria2" then
						return (server.fast_open == "1") and true or nil
					else
						return nil
					end
				end)(), -- XHTTP Tcp Fast Open
				tcpMptcp = (server.mptcp == "1") and true or nil, -- MPTCP
				Penetrate = (server.mptcp == "1") and true or nil, -- Penetrate MPTCP
				tcpcongestion = server.custom_tcpcongestion, -- 连接服务器节点的 TCP 拥塞控制算法
				-- 出站的 dialerProxy（与 fragment 中的 tag 保持一致）
				dialerProxy = (xray_fragment.fragment == "1" or xray_fragment.noise == "1") and
				              ((remarks and remarks ~= "") and (node_id .. "." .. remarks) or ("direct" .. "." .. node_id)) or nil
			}
		} or nil,
		mux = (server.v2ray_protocol ~= "hysteria2" and server.v2ray_protocol ~= "wireguard") and {
			-- mux
			enabled = (server.mux == "1"), -- Mux
			concurrency = (server.mux == "1" and (tonumber(server.concurrency) or -1)) or nil, -- TCP 最大并发连接数
			xudpConcurrency = (server.mux == "1" and (tonumber(server.xudpConcurrency) or 16)) or nil, -- UDP 最大并发连接数
			xudpProxyUDP443 = (server.mux == "1" and (server.xudpProxyUDP443 or "reject")) or nil -- 对被代理的 UDP/443 流量处理方式
		} or nil
	}
}

if xray_builtin_dns then
	table.insert(Xray.outbounds, {
		protocol = "dns",
		tag = "builtin-dns-out",
		settings = {
			network = "tcp",
			address = xray_builtin_dns.address,
			port = xray_builtin_dns.port
		}
	})
	Xray.routing = Xray.routing or {}
	Xray.routing.rules = Xray.routing.rules or {}
	table.insert(Xray.routing.rules, {
		type = "field",
		inboundTag = { "builtin-dns-in" },
		outboundTag = "builtin-dns-out"
	})
end

-- 添加带有 fragment 设置的 dialerproxy 配置
if xray_fragment.fragment ~= "0" or (xray_fragment.noise ~= "0" and xray_noise.enabled ~= "0") then
	local n_domainstrategy = xray_noise.domainStrategy
	table.insert(Xray.outbounds, {
		protocol = "freedom",
		tag = (remarks and remarks ~= "") and (node_id .. "." .. remarks) or ("direct" .. "." .. node_id),
		settings = (xray_fragment.noise == "1" and xray_noise.enabled == "1") and n_domainstrategy and n_domainstrategy ~= "" and {
			domainStrategy = n_domainstrategy
		} or nil,
		streamSettings = {
			sockopt = {
			mark = 255,
			tcpFastOpen = (function()
				if server.transport == "xhttp" then
					return (server.fast_open == "1") and true or false
				elseif server.v2ray_protocol == "hysteria2" then
					return (server.fast_open == "1") and true or nil
				else
					return nil
				end
			end)(), -- XHTTP Tcp Fast Open
			tcpMptcp = (server.mptcp == "1") and true or nil, -- MPTCP
			Penetrate = (server.mptcp == "1") and true or nil, -- Penetrate MPTCP
			tcpcongestion = server.custom_tcpcongestion -- 连接服务器节点的 TCP 拥塞控制算法
			}
		}
	})
end

local cipher = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
local cipher13 = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
local trojan = {
	log_level = 3,
	run_type = (proto == "nat" or proto == "tcp") and "nat" or "client",
	local_addr = "0.0.0.0",
	local_port = tonumber(local_port),
	remote_addr = server.server,
	remote_port = tonumber(server.server_port),
	udp_timeout = 60,
	-- 传入连接
	password = {server.password},
	-- 传出连接
	ssl = {
		verify = (server.insecure == "0") and true or false,
		verify_hostname = (server.tls == "1") and true or false,
		cert = (server.certificate) and server.certpath or nil,
		cipher = cipher,
		cipher_tls13 = cipher13,
		sni = server.tls_host,
		alpn = (server.tls == "1") and (function()
			local alpn = {}
			if server.tls_alpn and server.tls_alpn ~= "" then
				string.gsub(server.tls_alpn, '[^,]+', function(w)
					table.insert(alpn, w)
				end)
			end
			if #alpn > 0 then
				return alpn
			else
				return nil
			end
		end)() or {"h2", "http/1.1"},
		curve = "",
		reuse_session = true,
		session_ticket = (server.tls_sessionTicket == "1") and true or false
	},
	tcp = {
		-- tcp
		no_delay = true,
		keep_alive = true,
		reuse_port = true,
		fast_open = (server.fast_open == "1") and true or false,
		fast_open_qlen = 20
	}
}
local naiveproxy = {
	proxy = (server.username and server.password and server.server and server.server_port) and "https://" .. server.username .. ":" .. server.password .. "@" .. format_host_port(server.server, server.server_port),
	listen = (proto == "redir") and "redir" .. "://0.0.0.0:" .. tonumber(local_port) or "socks" .. "://0.0.0.0:" .. tonumber(local_port),
	["insecure-concurrency"] = tonumber(server.concurrency) or 1
}
local ss = {
	server = (server.kcp_enable == "1") and "127.0.0.1" or server.server,
	server_port = tonumber(server.server_port),
	local_address = "0.0.0.0",
	local_port = tonumber(local_port),
	mode = (proto == "tcp,udp") and "tcp_and_udp" or (proto .. "_only"),
	password = server.password,
	method = server.encrypt_method_ss,
	timeout = tonumber(server.timeout),
	fast_open = (server.fast_open == "1") and true or false,
	reuse_port = true
}
local hysteria2 = {
	server = (
		server.server_port and 
		(
			server.port_range and 
			(format_host_port(server.server, server.server_port) .. "," .. string.gsub(server.port_range, ":", "-")) 
			or 
			(format_host_port(server.server, server.server_port))
		) 
		or 
		(
			server.port_range and 
			format_host(server.server) .. ":" .. string.gsub(server.port_range, ":", "-") 
			or 
			server.server and format_host_port(server.server, "443")
		)
	),
	bandwidth = (server.uplink_capacity or server.downlink_capacity) and {
		up = tonumber(server.uplink_capacity) and tonumber(server.uplink_capacity) .. " mbps" or nil,
		down = tonumber(server.downlink_capacity) and tonumber(server.downlink_capacity) .. " mbps" or nil
	} or nil,
	realm = (server.hysteria2_realms and server.hysteria2_realm_stun) and {
		stunServers = server.hysteria2_realm_stun
	} or nil,
	socks5 = (proto:find("tcp") and tonumber(socks_port) and tonumber(socks_port) ~= 0) and {
		listen = "0.0.0.0:" .. tonumber(socks_port),
		disableUDP = false
	} or nil,
	transport = {
		type = server.transport_protocol or "udp",
		udp = server.port_range and (function()
			local udp = {}
			local t = server.hopinterval
			if not t then return nil end
			if t:find("-", 1, true) then
				local min, max = t:match("^(%d+)%-(%d+)$")
				min = tonumber(min)
				max = tonumber(max)
				if min and max then
					min = (min >= 5) and min or 5
					max = (max >= min) and max or min
					udp.minHopInterval = min .. "s"
					udp.maxHopInterval = max .. "s"
					return udp
				end
			end
			t = tonumber((t or "30"):match("^%d+"))
			t = (t and t >= 5) and t or 30
			udp.hopInterval = t .. "s"
			return udp
		end)() or nil
	},
--[[
	tcpTProxy = (proto:find("tcp") and local_port ~= "0") and {
		listen = "0.0.0.0:" .. tonumber(local_port)
	} or nil,
]]--
	tcpRedirect = (proto:find("tcp") and local_port ~= "0") and {
		listen = "0.0.0.0:" .. tonumber(local_port)
	} or nil,
	udpTProxy = (proto:find("udp") and local_port ~= "0") and {
		listen = "0.0.0.0:" .. tonumber(local_port)
	} or nil,
	obfs = (server.flag_obfs == "1") and {
		type = server.obfs_type,
		[server.obfs_type] = { password = server.salamander }
	} or nil,
	quic = (server.flag_quicparam == "1" ) and {
		initStreamReceiveWindow = (server.initstreamreceivewindow and server.initstreamreceivewindow or nil),
		maxStreamReceiveWindow = (server.maxstreamreceivewindow and server.maxstreamreceivewindow or nil),
		initConnReceiveWindow = (server.initconnreceivewindow and server.initconnreceivewindow or nil),
		maxConnReceiveWindow = (server.maxconnreceivewindow and server.maxconnreceivewindow or nil),
		maxIdleTimeout = (tonumber(server.maxidletimeout) and tonumber(server.maxidletimeout) .. "s" or nil),
		keepAlivePeriod = (tonumber(server.keepaliveperiod) and tonumber(server.keepaliveperiod) .. "s" or nil),
		disablePathMTUDiscovery = (server.disablepathmtudiscovery == "1") and true or false
	} or nil,
	auth = server.hy2_auth,
	tls = (server.tls_host and server.tls_host ~= "") and {
		sni = server.tls_host,
		alpn = (server.tls_alpn and server.tls_alpn ~= "") and (function()
			local alpn = {}
			string.gsub(server.tls_alpn, '[^,]+', function(w)
				table.insert(alpn, w)
			end)
			if #alpn > 0 then
				return alpn
			else
				return nil
			end
		end)() or nil,
		--sni = server.tls_host or (server.tls_host and server.tls_alpn) or nil,
		insecure = (server.insecure == "1") and true or false,
		pinSHA256 = server.pinsha256 or nil
	} or {
		sni = server.server,
		alpn = (server.type == "hysteria2") and (function()
			local alpn = {}
			if server.tls_alpn and server.tls_alpn ~= "" then
				string.gsub(server.tls_alpn, '[^,]+', function(w)
					table.insert(alpn, w)
				end)
			end
			if #alpn > 0 then
				return alpn
			else
				return nil
			end
		end)() or nil,
		insecure = (server.insecure == "1") and true or false,
		pinSHA256 = server.pinsha256 or nil
	},
	fast_open = (server.fast_open == "1") and true or false,
	lazy = (server.lazy_mode == "1") and true or false
}
if hysteria2.obfs and hysteria2.obfs.type == "gecko" then
	local min = tonumber(server.obfs_MinPacketSize) or 512
	local max = tonumber(server.obfs_MaxPacketSize) or 1200
	if min <= 0 or min > max or max > 2048 then
        	min = 512
        	max = 1200
	end
	hysteria2.obfs.gecko.minPacketSize = min
	hysteria2.obfs.gecko.maxPacketSize = max
end
local shadowtls = {
	client = {
		server_addr = server.server_port and format_host_port(server.server, server.server_port) or nil,
		listen = "127.0.0.1:" .. tonumber(local_port),
		tls_names = server.shadowtls_sni,
		password = server.password
	},
	v3 = (server.shadowtls_protocol == "v3") and true or false,
	disable_nodelay = (server.disable_nodelay == "1") and true or false,
	fastopen = (server.fastopen == "1") and true or false,
	strict = (server.strict == "1") and true or false
}
local chain_sslocal = {
	locals = local_port ~= "0" and {
		{
			local_address = "0.0.0.0",
			local_port = (chain_local_port == "0" and effective_node_local_port or tonumber(chain_local_port)),
			mode = (proto:find("tcp,udp") and "tcp_and_udp") or proto .. "_only",
			protocol = "redir",
			tcp_redir = "redirect",
			--tcp_redir = "tproxy",
			udp_redir = "tproxy"
		},
		socks_port ~= "0" and {
			protocol = "socks",
			local_address = "0.0.0.0",
			local_port = tonumber(socks_port)
		} or nil
	} or {{
		protocol = "socks",
		local_address = "0.0.0.0",
		local_port = tonumber(socks_port)
	}},
	servers = {
		{
			server = "127.0.0.1",
			server_port = (tonumber(local_port) == 0 and tonumber(chain_local_port) or tonumber(local_port)),
			method = server.sslocal_method,
			password = server.sslocal_password
		}
	}
}
local chain_vmess = {
	inbounds = (local_port ~= "0") and {
		{
			port = (chain_local_port == "0" and effective_node_local_port or tonumber(chain_local_port)),
			protocol = "dokodemo-door",
			settings = {
				network = proto,
				followRedirect = true
			},
			streamSettings = {
				sockopt = {tproxy = "redirect"}
			},
			sniffing = {
				enable = true,
				destOverride = {"http","tls"}
			}
		},
		(proto:find("tcp") and socks_port ~= "0") and {
			protocol = "socks",
			port = tonumber(socks_port)
		} or nil
	} or { protocol = "socks", port = tonumber(socks_port) },
	outbound = {
		protocol = "vmess",
		settings = {
			vnext = {{
				address = "127.0.0.1",
				port = (tonumber(local_port) == 0 and tonumber(chain_local_port) or tonumber(local_port)),
				users = {{
					id = (server.vmess_uuid),
					security = server.vmess_method,
					level = 0
				}}
			}}
		}
	}
}
local tuic = {
	relay = {
		server = server.server_port and format_host_port(server.server, server.server_port),
		ip = server.tuic_ip,
		uuid = server.tuic_uuid,
		password = server.tuic_passwd,
		certificates = server.certificate and { server.certpath } or nil,
		udp_relay_mode = server.udp_relay_mode,
		congestion_control = server.congestion_control,
		heartbeat = server.heartbeat and tonumber(server.heartbeat) .. "s" or nil,
		timeout = server.timeout and tonumber(server.timeout) .. "s" or nil,
		gc_interval = server.gc_interval and tonumber(server.gc_interval) .. "s" or nil,
		gc_lifetime = server.gc_lifetime and tonumber(server.gc_lifetime) .. "s" or nil,
		alpn = (server.tuic_alpn and server.tuic_alpn ~= "") and (function()
			local alpn = {}
			string.gsub(server.tuic_alpn, '[^,]+', function(w)
				table.insert(alpn, w)
			end)
			if #alpn > 0 then
				return alpn
			else
				return nil
			end
		end)() or nil,
		ipstack_prefer = (server.tuic_dual_stack == "1") and server.ipstack_prefer or nil,
		skip_cert_verify = (server.insecure == "1" or server.insecure == true or server.insecure == "true"),
		disable_sni = (server.disable_sni == "1") and true or false,
		zero_rtt_handshake = (server.zero_rtt_handshake == "1") and true or false,
		send_window = tonumber(server.send_window),
		receive_window = tonumber(server.receive_window)
	},
	["local"] = {
		server = tonumber(socks_port) and "[::]:" .. (socks_port == "0" and local_port or tonumber(socks_port)),
		dual_stack = (server.tuic_dual_stack == "1") and true or nil,
		max_packet_size = tonumber(server.tuic_max_package_size)
	}
}

local config = {}
function config:new(o)
	o = o or {}
	setmetatable(o, self)
	self.__index = self
	return o
end
function config:handleIndex(index)
	local switch = {
		ss = function()
			ss.protocol = socks_port
			if server.enable_plugin == "1" and server.plugin and server.plugin ~= "none" then
				if server.plugin == "custom" then
					ss.plugin = server.custom_plugin
				else
					ss.plugin = server.plugin
				end
				ss.plugin_opts = server.plugin_opts or nil
			end
			print(json.stringify(ss, 1))
		end,
		ssr = function()
			ss.protocol = server.protocol
			ss.protocol_param = server.protocol_param
			ss.method = server.encrypt_method
			ss.obfs = server.obfs
			ss.obfs_param = server.obfs_param
			print(json.stringify(ss, 1))
		end,
		v2ray = function()
			print(json.stringify(Xray, 1))
		end,
		trojan = function()
			print(json.stringify(trojan, 1))
		end,
		naiveproxy = function()
			print(json.stringify(naiveproxy, 1))
		end,
		hysteria2 = function()
			print(json.stringify(hysteria2, 1))
		end,
		shadowtls = function()
			local chain_switch = {
				sslocal = function()
					if (chain:find("chain")) then
						print(json.stringify(chain_sslocal, 1))
					else
						print(json.stringify(shadowtls, 1))
					end
				end,
				vmess = function()
					if (chain:find("chain")) then
						print(json.stringify(chain_vmess, 1))
					else
						print(json.stringify(shadowtls, 1))
					end
				end
			}
			local ChainType = server.chain_type
			if chain_switch[ChainType] then
				chain_switch[ChainType]()
			end
		end,
		tuic = function()
			print(json.stringify(tuic, 1))
		end
	}
	if switch[index] then
		switch[index]()
	end
end
local f = config:new()
f:handleIndex(server.type)
