#!/usr/bin/lua
-- Run on OpenWrt with the installed Lua dependencies; reads UCI, never updates it.
-- lua subscribe-ss.lua /path/to/subscribe.lua
local path = arg[1] or "/usr/share/shadowsocksr/subscribe.lua"
local file = assert(io.open(path))
local source = file:read("*a")
file:close()
source = source:gsub("^#![^\n]*", "")
local boundary = assert(source:find("\nlocal function md5_string", 1, true))
-- Load only the parser definitions, stopping before subscription execution.
local parse = assert(loadstring(source:sub(1, boundary - 1) .. [[
has_xray, has_ss_rust, has_mihomo = true, false, false
return processData
]], "@" .. path))()
local b64 = require("nixio").bin.b64encode
local count = 0
local function check(label, link, expected)
	local ok, node = pcall(parse, "ss", link)
	assert(ok, label .. ": parser raised an error")
	if expected then
		assert(node, label .. ": node rejected")
		assert(node.type == "v2ray" and node.v2ray_protocol == "shadowsocks", label .. ": wrong backend")
		for key, value in pairs(expected) do
			assert(tostring(node[key]) == tostring(value), label .. ": incorrect " .. key)
		end
	else
		assert(node == nil, label .. ": malformed node accepted")
	end
	count = count + 1
end
local expected = {server="ss.example.com", server_port=20070, encrypt_method_ss="aes-256-gcm", password="test-password", alias="乌克兰W01"}
local suffix = "#%E4%B9%8C%E5%85%8B%E5%85%B0W01"
local full = b64("aes-256-gcm:test-password@ss.example.com:20070")
check("whole-link base64", full .. suffix, expected)
check("unpadded whole-link base64", full:gsub("=+$", "") .. suffix, expected)
check("SIP002", b64("aes-256-gcm:test-password") .. "@ss.example.com:20070" .. suffix, expected)
check("plaintext credentials", "aes-256-gcm:test-password@ss.example.com:20070" .. suffix, expected)
local password = "p@ss:word+/%?#"
local credentials = "aes-256-gcm:" .. password
for _,link in ipairs({b64(credentials .. "@ss.example.com:20070"), b64(credentials) .. "@ss.example.com:20070", b64(credentials):gsub("+", "-"):gsub("/", "_"):gsub("=+$", "") .. "@ss.example.com:20070"}) do
	check("reserved password characters", link, {password=password, server="ss.example.com", server_port=20070})
end
check("percent-encoded plaintext", "aes-256-gcm:p%40ss%3Aword+%2F%25%3F%23@ss.example.com:20070", {password=password})
check("legacy query", full .. "?type=ws&host=cdn.example.com&path=%2Fsocket&security=tls&sni=tls.example.com", {transport="ws", ws_path="/socket", tls="1", tls_host="tls.example.com"})
check("UUID extension", "12345678-1234-1234-1234-123456789abc@ss.example.com:443?encryption=none&type=ws", {password="12345678-1234-1234-1234-123456789abc", encrypt_method_ss="none", transport="ws"})
check("IPv6", b64("aes-256-gcm:test-password@[2001:db8::1]:443"), {server="2001:db8::1", server_port=443})
for _,link in ipairs({"", "invalid", b64("missing-separator"), b64("aes-256-gcm:password@ss.example.com"), "aes-256-gcm:password@:443", b64(":password@ss.example.com:443")}) do
	check("malformed input", link, nil)
end
print("SS subscription parser: " .. count .. " cases passed")
