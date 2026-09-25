-- Synthetic large-profile measurement of the real rule postprocessor.
local helper = arg[1] or "luci-app-ssr-plus/root/usr/share/shadowsocksr/clash_yaml.lua"
local document, rendered
local prefix = table.concat({
	"mode: rule\n",
	"proxies:\n",
	"  - name: udp-on\n    type: socks5\n    server: 192.0.2.1\n    port: 1080\n    udp: true\n",
	"  - name: udp-off\n    type: socks5\n    server: 192.0.2.2\n    port: 1080\n    udp: false\n",
	"proxy-groups:\n",
	"  - name: PROXY\n    type: select\n    proxies: [udp-on, udp-off]\n",
	"rules:\n"
})
local function serialize(doc)
	local lines = {prefix}
	for _, rule in ipairs(doc.rules) do lines[#lines + 1] = "  - " .. rule .. "\n" end
	return table.concat(lines)
end
_G.nixio = {fs = {
	readfile = function() return "fixture" end,
	writefile = function(_, data) rendered = data; return true end
}}
package.preload["nixio"] = function() return nixio end
package.preload["nixio.fs"] = function() return nixio.fs end
package.preload["luci.model.uci"] = function()
	return {cursor = function() return {get_first = function(_, _, _, _, default) return default end} end}
end
package.preload["lyaml"] = function()
	return {load = function() return document end,
		dump = function(docs) return serialize(docs[1]) end}
end
local exit = os.exit
os.exit = function(status) assert(status == 0) end

document = {proxies = {{name = "udp-on", udp = true}, {name = "udp-off", udp = false}},
	["proxy-groups"] = {{name = "PROXY", proxies = {"udp-on", "udp-off"}}}, rules = {}}
local bytes = #prefix
local index = 0
while bytes < 583 * 1024 - 100 do
	index = index + 1
	local rule = string.format("DOMAIN-SUFFIX,domain%08d.example,PROXY", index)
	document.rules[#document.rules + 1] = rule
	bytes = bytes + #rule + 5
end
document.rules[#document.rules + 1] = "MATCH,PROXY"
local original = #serialize(document)
local previous = original
for _, rule in ipairs(document.rules) do
	local matcher = rule:match("^(.*),PROXY$")
	local guard = matcher == "MATCH" and "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT" or
		"AND,((NETWORK,UDP),(DST-PORT,443),(" .. matcher .. ")),REJECT"
	previous = previous + #guard + 5
end
arg = {"guard_udp443", "fixture.yaml"}
assert(loadfile(helper))()
local compact = #rendered
assert(#document.rules == index + 2, "only the terminal guard is needed")
assert(compact < previous / 2, "large tail should save over half of the prior output")
os.exit = exit
print(string.format("PASS: %d proxy rules; synthetic YAML %d -> old %d -> compact %d bytes",
	index, original, previous, compact))
