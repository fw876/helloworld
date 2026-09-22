-- Run from the repository root: lua luci-app-ssr-plus/tests/test_inbound_tcpcongestion.lua
local generator = arg[1] or "luci-app-ssr-plus/root/usr/share/shadowsocksr/gen_config.lua"
local output, available, proc_missing
local server
local original_open, original_print = io.open, print

package.preload["luci.sys"] = function()
	_G.luci = {sys = {exec = function(command)
		if command:find("xray version", 1, true) then return "Xray 26.7.11" end
		return ""
	end}}
	_G.nixio = {bin = {b64decode = function(s) return s end, b64encode = function(s) return s end}}
	return luci.sys
end
package.preload["luci.model.uci"] = function()
	return {cursor = function() return {
		get_all = function(_, _, section)
			if section == "testnode" then return server end
			return {}
		end,
		get_first = function(_, _, _, _, default) return default end
	} end}
end
package.preload["luci.jsonc"] = function()
	return {stringify = function(value) output = value; return "{}" end, parse = function() return {} end}
end
package.preload["luci.cbi.datatypes"] = function() return {ip6addr = function() return false end} end
io.open = function(path, ...)
	if path == "/proc/sys/net/ipv4/tcp_available_congestion_control" then
		if proc_missing then return nil end
		return {read = function() return available end, close = function() end}
	end
	return original_open(path, ...)
end
print = function() end

local function generate(value, proto, port, socks, algorithms)
	server = {type = "v2ray", v2ray_protocol = "vless", server = "192.0.2.1",
		server_port = "443", vmess_id = "00000000-0000-4000-8000-000000000001",
		transport = "raw", custom_tcpcongestion = "cubic", inbound_tcpcongestion = value}
	available = algorithms or "reno cubic bbr\n"
	arg = {"testnode", proto or "tcp,udp", port or "1234", socks or "1080"}
	output = nil
	assert(loadfile(generator))()
	assert(output, "generator must produce a config")
	return output
end

for _, value in ipairs({false, ""}) do
	local config = generate(value or nil)
	for _, inbound in ipairs(config.inbounds) do
		assert(inbound.streamSettings == nil, "default must not alter inbound sockets")
	end
end
for _, value in ipairs({"bbr", "cubic", "reno"}) do
	for _, proto in ipairs({"tcp", "tcp,udp"}) do
		local config = generate(value, proto)
		assert(#config.inbounds == 2)
		assert(config.inbounds[1].settings.followRedirect == true)
		assert(config.inbounds[1].settings.network == proto)
		for _, inbound in ipairs(config.inbounds) do
			assert(inbound.streamSettings.sockopt.tcpcongestion == value)
		end
		assert(config.outbounds[1].streamSettings.sockopt.tcpcongestion == "cubic", "outbound must remain independent")
	end
end
local udp = generate("bbr", "udp")
assert(#udp.inbounds == 1 and udp.inbounds[1].streamSettings == nil)
local socks_only = generate("bbr", "tcp", "0")
assert(#socks_only.inbounds == 1 and socks_only.inbounds[1].protocol == "socks")
assert(socks_only.inbounds[1].streamSettings.sockopt.tcpcongestion == "bbr")
assert(#generate("bbr", "tcp", "0", "0").inbounds == 0)
assert(generate("bbr", "tcp", "1234", "0").inbounds[1].streamSettings.sockopt.tcpcongestion == "bbr")
assert(generate("bbr", "tcp", nil, nil, "reno cubic").inbounds[1].streamSettings == nil)
assert(generate("not-an-algorithm").inbounds[1].streamSettings == nil)
proc_missing = true
assert(generate("bbr").inbounds[1].streamSettings == nil)
io.open, print = original_open, original_print
print("PASS: inbound congestion defaults, TCP/UDP, SOCKS, kernel availability and outbound independence")
