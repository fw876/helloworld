-- Exercise the real UCI-to-Xray generator using the existing node UI fields.
local generator = arg[1] or "luci-app-ssr-plus/root/usr/share/shadowsocksr/gen_config.lua"
local server, output
local original_print = print
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
		get_all = function(_, _, section) return section == "testnode" and server or {} end,
		get_first = function(_, _, _, _, default) return default end
	} end}
end
package.preload["luci.jsonc"] = function()
	return {stringify = function(value) output = value; return "{}" end, parse = function() return {} end}
end
package.preload["luci.cbi.datatypes"] = function() return {ip6addr = function() return false end} end
print = function() end

local function generate(fields, network)
	server = {type = "v2ray", v2ray_protocol = "vless", server = "192.0.2.1",
		server_port = "443", vmess_id = "00000000-0000-4000-8000-000000000001",
		transport = "raw", tls = "1"}
	for key, value in pairs(fields) do server[key] = value end
	arg = {"testnode", network, "12345", "0"}
	output = nil
	assert(loadfile(generator))()
	assert(output and output.outbounds[1], "missing generated outbound")
	return output.outbounds[1]
end

for _, network in ipairs({"tcp,udp", "udp"}) do
	for _, flow in ipairs({"none", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}) do
		local outbound = generate({tls_flow = flow}, network)
		local expected = flow ~= "none" and flow or nil
		assert(outbound.settings.vnext[1].users[1].flow == expected)
	end
	-- Saved flow preferences do not necessarily reach the running config.
	for _, fields in ipairs({
		{tls_flow = "xtls-rprx-vision", tls = "0"},
		{tls_flow = "xtls-rprx-vision", transport = "ws"},
		{tls_flow = "xtls-rprx-vision", v2ray_protocol = "vmess"}
	}) do
		assert(generate(fields, network).settings.vnext[1].users[1].flow == nil)
	end
	for _, policy in ipairs({"reject", "allow", "skip"}) do
		local outbound = generate({mux = "1", xudpProxyUDP443 = policy,
			concurrency = "-1", xudpConcurrency = "16"}, network)
		assert(outbound.mux.enabled == true and outbound.mux.xudpProxyUDP443 == policy)
		assert(outbound.mux.concurrency == -1 and outbound.mux.xudpConcurrency == 16)
		outbound = generate({mux = "0", xudpProxyUDP443 = policy}, network)
		assert(outbound.mux.enabled == false and outbound.mux.xudpProxyUDP443 == nil)
	end
	assert(generate({mux = "1"}, network).mux.xudpProxyUDP443 == "reject")
end
print = original_print
print("PASS: existing Flow/Mux UI fields reach shared and separate UDP configs; inapplicable settings are omitted")
