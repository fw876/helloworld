-- Exercise the CBI declaration itself, without a running LuCI web server.
local path = arg[1] or "luci-app-ssr-plus/luasrc/model/cbi/shadowsocksr/client-config.lua"
local file = assert(io.open(path))
local source = file:read("*a")
file:close()
local declaration = assert(source:match("%-%- Client%-facing TCP sockets[^\n]*\n(.-)\n%-%- %[%[ HYSTERIA2_tcpcongestion"))
local function form(xray, mihomo, use_mihomo, algorithms)
	local option
	local env = {
		is_finded = function(name) return name == "xray" and xray end,
		has_mihomo = mihomo,
		uci = {get_first = function() return use_mihomo end},
		nixio = {fs = {readfile = function() return algorithms end}},
		translate = function(text) return text end,
		ListValue = "ListValue",
		s = {option = function(_, kind, key)
			assert(kind == "ListValue" and key == "inbound_tcpcongestion")
			option = {key = key, choices = {}}
			function option:value(value, label) self.choices[value] = label end
			function option:depends(key, value) self.dependency = {key, value} end
			return option
		end}
	}
	if setfenv then
		setfenv(assert(loadstring(declaration)), env)()
	else
		assert(load(declaration, "CBI inbound congestion option", "t", env))()
	end
	return option
end
local option = assert(form(true, false, nil, "reno cubic bbr\n"))
assert(option.default == "" and option.rmempty == true)
assert(option.dependency[1] == "type" and option.dependency[2] == "v2ray")
assert(option.choices[""] and option.choices.bbr and option.choices.cubic and option.choices.reno)
assert(not option.choices.brutal, "unavailable algorithms must not be offered")
assert(not form(true, false, nil, "reno cubic").choices.bbr)
assert(form(true, false, nil, nil).choices[""])
assert(form(false, false, nil, "bbr") == nil)
assert(form(true, true, "1", "bbr") == nil, "do not expose an ignored setting for Mihomo")
assert(form(true, true, "0", "bbr").choices.bbr)
print("PASS: CBI key, default, kernel choices, node dependency and active-core gating")
