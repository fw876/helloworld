-- Copyright (C) 2017 yushi studio <ywb94@qq.com>
-- Licensed to the public under the GNU General Public License v3.
module("luci.controller.shadowsocksr", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/shadowsocksr") then
		call("act_reset")
	end
	local page
	page = entry({"admin", "services", "shadowsocksr"}, alias("admin", "services", "shadowsocksr", "client"), _("ShadowSocksR Plus+"), 10)
	page.dependent = true
	page.acl_depends = { "luci-app-ssr-plus" }
	entry({"admin", "services", "shadowsocksr", "client"}, cbi("shadowsocksr/client"), _("SSR Client"), 10).leaf = true
	entry({"admin", "services", "shadowsocksr", "servers"}, arcombine(cbi("shadowsocksr/servers", {autoapply = true}), cbi("shadowsocksr/client-config")), _("Servers Nodes"), 20).leaf = true
	entry({"admin", "services", "shadowsocksr", "control"}, cbi("shadowsocksr/control"), _("Access Control"), 30).leaf = true
	entry({"admin", "services", "shadowsocksr", "advanced"}, cbi("shadowsocksr/advanced"), _("Advanced Settings"), 50).leaf = true
	entry({"admin", "services", "shadowsocksr", "server"}, arcombine(cbi("shadowsocksr/server"), cbi("shadowsocksr/server-config")), _("SSR Server"), 60).leaf = true
	entry({"admin", "services", "shadowsocksr", "status"}, form("shadowsocksr/status"), _("Status"), 70).leaf = true
	entry({"admin", "services", "shadowsocksr", "check"}, call("check_status"))
	entry({"admin", "services", "shadowsocksr", "refresh"}, call("refresh_data"))
	entry({"admin", "services", "shadowsocksr", "subscribe"}, call("subscribe"))
	entry({"admin", "services", "shadowsocksr", "checkport"}, call("check_port"))
	entry({"admin", "services", "shadowsocksr", "log"}, form("shadowsocksr/log"), _("Log"), 80).leaf = true
	entry({"admin", "services", "shadowsocksr", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", "shadowsocksr", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", "shadowsocksr", "run"}, call("act_status"))
	entry({"admin", "services", "shadowsocksr", "ping"}, call("act_ping"))
	entry({"admin", "services", "shadowsocksr", "reset"}, call("act_reset"))
	entry({"admin", "services", "shadowsocksr", "restart"}, call("act_restart"))
	entry({"admin", "services", "shadowsocksr", "delete"}, call("act_delete"))
		--[[Backup]]
	entry({"admin", "services", "shadowsocksr", "backup"}, call("create_backup")).leaf = true
	
end

function subscribe()
	luci.sys.call("/usr/bin/lua /usr/share/shadowsocksr/subscribe.lua >>/var/log/ssrplus.log")
	luci.http.prepare_content("application/json")
	luci.http.write_json({ret = 1})
end

function act_status()
	local e = {}
	e.running = luci.sys.call("busybox ps -w | grep ssr-retcp | grep -v grep >/dev/null") == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function act_ping()
    local e = {}
    local domain = luci.http.formvalue("domain")
    local port = tonumber(luci.http.formvalue("port") or 0)
    local transport = luci.http.formvalue("transport")
    local wsPath = luci.http.formvalue("wsPath") or ""
    local tls = luci.http.formvalue("tls")
    e.index = luci.http.formvalue("index")

    local use_nft = luci.sys.call("command -v nft >/dev/null") == 0
    local iret = false

    if use_nft then
        iret = luci.sys.call("nft add element inet ss_spec ss_spec_wan_ac { " .. domain .. " } 2>/dev/null") == 0
    else
        iret = luci.sys.call("ipset add ss_spec_wan_ac " .. domain .. " 2>/dev/null") == 0
    end

    if transport == "ws" then
        local prefix = tls == '1' and "https://" or "http://"
        local address = prefix .. domain .. ':' .. port .. wsPath
        local result = luci.sys.exec(
            "curl --http1.1 -m 2 -ksN -o /dev/null " ..
            "-w 'time_connect=%{time_connect}\nhttp_code=%{http_code}' " ..
            "-H 'Connection: Upgrade' -H 'Upgrade: websocket' " ..
            "-H 'Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==' " ..
            "-H 'Sec-WebSocket-Version: 13' " .. address
        )
        e.socket = string.match(result,"http_code=(%d+)") == "101"
        local ping_time = tonumber(string.match(result, "time_connect=(%d+.%d%d%d)"))
        e.ping = ping_time and ping_time * 1000 or nil
    else
        -- TCP ping
        local socket = nixio.socket("inet", "stream")
        socket:setopt("socket", "rcvtimeo", 3)
        socket:setopt("socket", "sndtimeo", 3)
        e.socket = socket:connect(domain, port)
        socket:close()

        e.ping = tonumber(luci.sys.exec(string.format(
            "tcping -q -c 1 -i 1 -t 2 -p %d %s 2>/dev/null | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}'",
            port, domain
        )))

        if not e.ping then
            e.ping = tonumber(luci.sys.exec(string.format(
                "ping -c 1 -W 1 %s 2>/dev/null | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}'",
                domain
            )))
        end

        if not e.ping then
            e.ping = tonumber(luci.sys.exec(string.format(
                "nping --udp -c 1 -p %d %s 2>/dev/null | grep -o 'Avg rtt: [0-9.]*ms' | awk '{print $3}' | sed 's/ms//' | head -1",
                port, domain
            )))
        end
    end

    if iret then
        if use_nft then
            luci.sys.call("nft delete element inet ss_spec ss_spec_wan_ac { " .. domain .. " } 2>/dev/null")
        else
            luci.sys.call("ipset del ss_spec_wan_ac " .. domain .. " 2>/dev/null")
        end
    end

    luci.http.prepare_content("application/json")
    luci.http.write_json(e)
end

function check_status()
	local e = {}
	e.ret = luci.sys.call("/usr/bin/ssr-check www." .. luci.http.formvalue("set") .. ".com 80 3 1")
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function refresh_data()
	local set = luci.http.formvalue("set")
	local retstring = loadstring("return " .. luci.sys.exec("/usr/bin/lua /usr/share/shadowsocksr/update.lua " .. set))()
	luci.http.prepare_content("application/json")
	luci.http.write_json(retstring)
end

function check_port()
	local retstring = "<br /><br />"
	local s
	local server_name = ""
	local uci = require "luci.model.uci".cursor()
	local use_nft = luci.sys.call("command -v nft >/dev/null") == 0

	uci:foreach("shadowsocksr", "servers", function(s)
		if s.alias then
			server_name = s.alias
		elseif s.server and s.server_port then
			server_name = s.server .. ":" .. s.server_port
		end

		-- 临时加入 set
		local iret = false
		if use_nft then
			iret = luci.sys.call("nft add element inet ss_spec ss_spec_wan_ac { " .. s.server .. " } 2>/dev/null") == 0
		else
			iret = luci.sys.call("ipset add ss_spec_wan_ac " .. s.server .. " 2>/dev/null") == 0
		end

		-- TCP 测试
		local socket = nixio.socket("inet", "stream")
		socket:setopt("socket", "rcvtimeo", 3)
		socket:setopt("socket", "sndtimeo", 3)
		local ret = socket:connect(s.server, s.server_port)
		socket:close()

		if ret then
			retstring = retstring .. string.format("<font><b style='color:green'>[%s] OK.</b></font><br />", server_name)
		else
			retstring = retstring .. string.format("<font><b style='color:red'>[%s] Error.</b></font><br />", server_name)
		end

		-- 删除临时 set
		if iret then
			if use_nft then
				luci.sys.call("nft delete element inet ss_spec ss_spec_wan_ac { " .. s.server .. " } 2>/dev/null")
			else
				luci.sys.call("ipset del ss_spec_wan_ac " .. s.server)
			end
		end
	end)

	luci.http.prepare_content("application/json")
	luci.http.write_json({ret = retstring})
end

function act_reset()
	luci.sys.call("/etc/init.d/shadowsocksr reset >/dev/null 2>&1")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr"))
end

function act_restart()
	luci.sys.call("/etc/init.d/shadowsocksr restart &")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr"))
end

function act_delete()
	luci.sys.call("/etc/init.d/shadowsocksr restart &")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shadowsocksr", "servers"))
end

function get_log()
	luci.http.write(luci.sys.exec("[ -f '/var/log/ssrplus.log' ] && cat /var/log/ssrplus.log"))
end
	
function clear_log()
	luci.sys.call("echo '' > /var/log/ssrplus.log")
end

function create_backup()
	local backup_files = {
		"/etc/config/shadowsocksr",
		"/etc/ssrplus/*"
	}
	local date = os.date("%Y-%m-%d-%H-%M-%S")
	local tar_file = "/tmp/shadowsocksr-" .. date .. "-backup.tar.gz"
	nixio.fs.remove(tar_file)
	local cmd = "tar -czf " .. tar_file .. " " .. table.concat(backup_files, " ")
	luci.sys.call(cmd)
	luci.http.header("Content-Disposition", "attachment; filename=shadowsocksr-" .. date .. "-backup.tar.gz")
	luci.http.header("X-Backup-Filename", "shadowsocksr-" .. date .. "-backup.tar.gz")
	luci.http.prepare_content("application/octet-stream")
	luci.http.write(nixio.fs.readfile(tar_file))
	nixio.fs.remove(tar_file)
end
