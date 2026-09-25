-- Test the real YAML postprocessor's rule order and selector-independent guards.
local helper = arg[1] or "luci-app-ssr-plus/root/usr/share/shadowsocksr/clash_yaml.lua"
local document, written
_G.nixio = {fs = {
	readfile = function() return "fixture" end,
	writefile = function() return true end
}}
package.preload["nixio"] = function() return nixio end
package.preload["nixio.fs"] = function() return nixio.fs end
package.preload["luci.model.uci"] = function()
	return {cursor = function() return {get_first = function(_, _, _, _, default) return default end} end}
end
package.preload["lyaml"] = function()
	return {
		load = function() return document end,
		dump = function(docs) written = docs[1]; return "---\n" end
	}
end
local exit = os.exit
os.exit = function(status) assert(status == 0, "postprocessor failed") end

document = {
	proxies = {{name = "udp-on", udp = true}, {name = "udp-off", udp = false}},
	["proxy-groups"] = {{name = "PROXY", type = "select", proxies = {"udp-on", "udp-off"}}},
	rules = {
		"DOMAIN-SUFFIX,local.example,DIRECT",
		"DOMAIN-SUFFIX,foreign.example,PROXY",
		"DOMAIN-SUFFIX,foreign.example,DIRECT",
		"AND,((DOMAIN,other.example),(DST-PORT,443)),PROXY",
		"IP-CIDR,198.18.0.0/16,udp-off,no-resolve",
		"IP-CIDR,203.0.113.0/24,PROXY,src",
		"SUB-RULE,(NETWORK,UDP),nested",
		"DOMAIN,tail1.example,PROXY",
		"DOMAIN,tail2.example,PROXY",
		"DOMAIN,tail3.example,PROXY",
		"MATCH,PROXY"
	},
	["sub-rules"] = {nested = {"DOMAIN,local.example,DIRECT", "MATCH,udp-off"}}
}

local function run(expect_write)
	written = nil
	arg = {"guard_udp443", "fixture.yaml"}
	assert(loadfile(helper))()
	assert((written == document) == expect_write)
end
run(true)
local expected = {
	"DOMAIN-SUFFIX,local.example,DIRECT",
	"DOMAIN-SUFFIX,foreign.example,PROXY",
	"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,foreign.example)),REJECT",
	"DOMAIN-SUFFIX,foreign.example,DIRECT",
	"AND,((DOMAIN,other.example),(DST-PORT,443)),PROXY",
	"AND,((NETWORK,UDP),(DST-PORT,443),(AND,((DOMAIN,other.example),(DST-PORT,443)))),REJECT",
	"IP-CIDR,198.18.0.0/16,udp-off,no-resolve",
	"AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,198.18.0.0/16,no-resolve)),REJECT",
	"IP-CIDR,203.0.113.0/24,PROXY,src",
	"AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,203.0.113.0/24,src)),REJECT",
	"SUB-RULE,(NETWORK,UDP),nested",
	"DOMAIN,tail1.example,PROXY",
	"DOMAIN,tail2.example,PROXY",
	"DOMAIN,tail3.example,PROXY",
	"MATCH,PROXY",
	"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
}
assert(#document.rules == #expected)
for i, rule in ipairs(expected) do assert(document.rules[i] == rule, i .. ": " .. document.rules[i]) end
assert(document["sub-rules"].nested[1] == "DOMAIN,local.example,DIRECT")
assert(document["sub-rules"].nested[2] == "MATCH,udp-off")
assert(document["sub-rules"].nested[3] == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
run(false)
assert(#document.rules == #expected, "postprocessor must be idempotent")

-- A static selector containing only UDP-capable members needs no guard and
-- must not cause a wholesale YAML reserialization of a large profile.
document = {
	proxies = {{name = "udp-on", udp = true}},
	["proxy-groups"] = {{name = "CAPABLE", proxies = {"udp-on"}}},
	rules = {"DOMAIN-SUFFIX,fast.example,CAPABLE", "MATCH,CAPABLE"}
}
written = nil
arg = {"guard_udp443", "fixture.yaml"}
assert(loadfile(helper))()
assert(written == nil)
assert(#document.rules == 2)
os.exit = exit
print("PASS: Mihomo guards only possible UDP-incompatible routes; direct rules and selector choice are preserved")
