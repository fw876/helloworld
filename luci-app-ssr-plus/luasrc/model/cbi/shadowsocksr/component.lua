local m, s, o

m = SimpleForm(
	"component_update",
	translate("Component Update"),
	translate("Check installed component versions and upgrade them online from the upstream release page.")
)
m.reset = false
m.submit = false

s = m:section(SimpleSection)

o = m:field(ListValue, "component_mirror", translate("Mirror URL"))
o:value("direct", translate("GitHub Direct"))
o:value("gh-proxy", "gh-proxy.com")
o:value("gh-proxy_org", "gh-proxy.org")
o:value("ghproxy_link", "ghproxy.link")
o:value("ghfast", "ghfast.top")
o:value("jsdelivr", "cdn.jsdelivr.net")
o.rmempty = false
o.cfgvalue = function(self)
	return m.uci:get_first("shadowsocksr", "global", "component_mirror") or "direct"
end
o.write = function(self, section, value)
	m.uci:set("shadowsocksr", "@global[0]", "component_mirror", value)
	m.uci:commit("shadowsocksr")
end

s.template = "shadowsocksr/component"

return m
