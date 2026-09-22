-- Test the actual LuCI field declaration and stored UCI values.
local path = arg[1] or "luci-app-ssr-plus/luasrc/model/cbi/shadowsocksr/advanced.lua"
local file = assert(io.open(path))
local source = file:read("*a")
file:close()
local declaration = assert(source:match("%-%- Firewall policy[^\n]*\n(.-)\no = s:option%(Value, \"gfwlist_url\""))
local option
local env = {
	translate = function(text) return text end,
	ListValue = "ListValue",
	s = {option = function(_, kind, key, _, description)
		assert(kind == "ListValue" and key == "udp443_policy")
		option = {key = key, choices = {}, description = description}
		function option:value(value, label) self.choices[value] = label end
		return option
	end}
}
if setfenv then
	setfenv(assert(loadstring(declaration)), env)()
else
	assert(load(declaration, "CBI UDP/443 policy", "t", env))()
end
assert(option.default == "legacy" and option.rmempty == true)
assert(option.choices.legacy and option.choices.proxy and option.choices.reject)
local count = 0
for _ in pairs(option.choices) do count = count + 1 end
assert(count == 3)
assert(option.description:find("IPv4", 1, true))
assert(option.description:find("UDP-capable", 1, true))
assert(option.description:find("Vision and Mux", 1, true))
print("PASS: UDP/443 CBI key, legacy default, three policy values and prerequisites")
