-- Optional on-router config validation using real LuCI modules, without
-- reading/writing the installed UCI configuration or starting a listener:
-- lua tests/inbound_tcpcongestion_fixture.lua /path/to/gen_config.lua bbr > /tmp/test.json
-- xray run -test -config /tmp/test.json
local generator, algorithm = assert(arg[1]), arg[2]
local fixture = {
	type = "v2ray", v2ray_protocol = "vless", server = "192.0.2.1",
	server_port = "443", vmess_id = "00000000-0000-4000-8000-000000000001",
	transport = "raw", custom_tcpcongestion = "cubic", inbound_tcpcongestion = algorithm
}
package.loaded["luci.model.uci"] = {cursor = function() return {
	get_all = function(_, _, section) return section == "testnode" and fixture or {} end,
	get_first = function(_, _, _, _, default) return default end
} end}
arg = {"testnode", "tcp,udp", "12345", "12346"}
assert(loadfile(generator))()
