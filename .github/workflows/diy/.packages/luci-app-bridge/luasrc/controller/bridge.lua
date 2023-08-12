module("luci.controller.bridge", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/bridge") then
		return
	end

	local page

	page = entry({"admin", "network", "bridge"}, cbi("bridge"), _("Transparent bridge"), 60)
	page.dependent = true
	entry({"admin","network","bridge","status"},call("act_status")).leaf=true
end

function act_status()
  local e={}
  e.running=luci.sys.call("iptables -L INPUT | grep zone_.*input | grep bridge >/dev/null")==0
  luci.http.prepare_content("application/json")
  luci.http.write_json(e)
end
