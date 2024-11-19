#!/usr/bin/lua

------------------------------------------------
-- This file is part of the luci-app-ssr-plus update.lua
-- By Mattraks
------------------------------------------------
require "luci.sys"
require "luci.model.uci"
local icount = 0
local args = arg[1]
local uci = luci.model.uci.cursor()

-- 以下设置更新数据库至 DNSMASQ 配置路径
-- 获取 DNSMasq 配置 ID
local DEFAULT_DNSMASQ_CFGID = uci:get_first("dhcp", "dnsmasq", ".name")

if not DEFAULT_DNSMASQ_CFGID then
    error("未找到默认的 DNSMasq 配置 ID")
end

-- 查找包含 conf-dir 选项的 dnsmasq.conf 文件路径
local DNSMASQ_CONF_PATH_CMD = string.format("grep -l '^conf-dir=' /tmp/etc/dnsmasq.conf.%s*", DEFAULT_DNSMASQ_CFGID)
local DNSMASQ_CONF_PATH = io.popen(DNSMASQ_CONF_PATH_CMD):read("*l")

if not DNSMASQ_CONF_PATH or DNSMASQ_CONF_PATH:match("^%s*$") then
    error("无法找到包含 conf-dir 选项的 dnsmasq.conf 文件路径")
end

DNSMASQ_CONF_PATH = DNSMASQ_CONF_PATH:gsub("%s+", "") -- 去除空白字符

-- 获取 DNSMASQ 配置路径
local DNSMASQ_CONF_DIR_CMD = string.format("grep '^conf-dir=' %s | cut -d'=' -f2 | head -n 1", DNSMASQ_CONF_PATH)
local DNSMASQ_CONF_DIR = io.popen(DNSMASQ_CONF_DIR_CMD):read("*l")

if not DNSMASQ_CONF_DIR or DNSMASQ_CONF_DIR:match("^%s*$") then
    error("无法提取 conf-dir 配置，请检查 dnsmasq.conf 文件内容")
end

DNSMASQ_CONF_DIR = DNSMASQ_CONF_DIR:gsub("%s+", "") -- 去除空白字符

-- 设置 dnsmasq-ssrplus.d 目录路径，并去除路径末尾的斜杠
local TMP_DNSMASQ_PATH = DNSMASQ_CONF_DIR:match("^(.-)/?$") .. "/dnsmasq-ssrplus.d"

if not TMP_DNSMASQ_PATH or TMP_DNSMASQ_PATH:match("^%s*$") then
    error("无法找到包含 dnsmasq 选项的 dnsmasq-ssrplus.d 目录路径")
end

local TMP_PATH = "/var/etc/ssrplus"
-- match comments/title/whitelist/ip address/excluded_domain
local comment_pattern = "^[!\\[@]+"
local ip_pattern = "^%d+%.%d+%.%d+%.%d+"
local domain_pattern = "([%w%-%_]+%.[%w%.%-%_]+)[%/%*]*"
local excluded_domain = {
    "apple.com", "sina.cn", "sina.com.cn", "baidu.com", "byr.cn", "jlike.com", 
    "weibo.com", "zhongsou.com", "youdao.com", "sogou.com", "so.com", "soso.com", 
    "aliyun.com", "taobao.com", "jd.com", "qq.com"
}
-- gfwlist parameter
local mydnsip = '127.0.0.1'
local mydnsport = '5335'
local ipsetname = 'gfwlist'
local bc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
-- base64decoding
local function base64_dec(data)
	data = string.gsub(data, '[^' .. bc .. '=]', '')
	return (data:gsub('.', function(x)
		if (x == '=') then
			return ''
		end
		local r, f = '', (bc:find(x) - 1)
		for i = 6, 1, -1 do
			r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0')
		end
		return r;
	end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
		if (#x ~= 8) then
			return ''
		end
		local c = 0
		for i = 1, 8 do
			c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0)
		end
		return string.char(c)
	end))
end
-- check if domain is excluded
local function check_excluded_domain(value)
	for _, domain in ipairs(excluded_domain) do
		if value:find(domain) then
			return true
		end
	end
end
-- gfwlist转码至dnsmasq格式
local function generate_gfwlist(type)
    local domains, domains_map = {}, {}
    local out = io.open("/tmp/ssr-update." .. type, "w")
    for line in io.lines("/tmp/ssr-update.tmp") do
        if not (string.find(line, comment_pattern) or string.find(line, ip_pattern) or check_excluded_domain(line)) then
            local start, finish, match = string.find(line, domain_pattern)
            if start and not domains_map[match] then
                domains_map[match] = true
                table.insert(domains, match)
            end
        end
    end
    for _, domain in ipairs(domains) do
        out:write(string.format("server=/%s/%s#%s\n", domain, mydnsip, mydnsport))
        out:write(string.format("ipset=/%s/%s\n", domain, ipsetname))
    end
    out:close()
    os.remove("/tmp/ssr-update.tmp")
end

-- adblock转码至dnsmasq格式
local function generate_adblock(type)
	local domains, domains_map = {}, {}
	local out = io.open("/tmp/ssr-update." .. type, "w")
	for line in io.lines("/tmp/ssr-update.tmp") do
		if not (string.find(line, comment_pattern)) then
			local start, finish, match = string.find(line, domain_pattern)
			if start and not domains_map[match] then
				domains_map[match] = true
				table.insert(domains, match)
			end
		end
	end
	for _, domain in ipairs(domains) do
		out:write(string.format("address=/%s/\n", domain))
	end
	out:close()
	os.remove("/tmp/ssr-update.tmp")
end

local log = function(...)
	if args then
		print("{ret=" .. table.concat({...}, ",retcount=") .. "}")
	else
		print(os.date("%Y-%m-%d %H:%M:%S ") .. table.concat({...}, " "))
	end
end

local function update(url, file, type, file2)
	local Num = 1
	local refresh_cmd = "wget --no-check-certificate -q -O /tmp/ssr-update." .. type .. " " .. url
	local sret = luci.sys.call(refresh_cmd)
	if sret == 0 then
		if type == "gfw_data" then
			local gfwlist = io.open("/tmp/ssr-update." .. type, "r")
			local decode = gfwlist:read("*a")
			if not decode:find("google") then
				decode = base64_dec(decode)
			end
			gfwlist:close()
			-- 写回gfwlist
			gfwlist = io.open("/tmp/ssr-update.tmp", "w")
			gfwlist:write(decode)
			gfwlist:close()
			generate_gfwlist(type)
			Num = 2
		end
		if type == "ad_data" then
			local adblock = io.open("/tmp/ssr-update." .. type, "r")
			local decode = adblock:read("*a")
			if decode:find("address=") then
				adblock:close()
			else
				adblock:close()
				-- 写回adblock
				adblock = io.open("/tmp/ssr-update.tmp", "w")
				adblock:write(decode)
				adblock:close()
				generate_adblock(type)
			end
		end
		local new_md5 = luci.sys.exec("echo -n $([ -f '/tmp/ssr-update." .. type .. "' ] && md5sum /tmp/ssr-update." .. type .. " | awk '{print $1}')")
		local old_md5 = luci.sys.exec("echo -n $([ -f '" .. file .. "' ] && md5sum " .. file .. " | awk '{print $1}')")
		if new_md5 == old_md5 then
			if args then
				log(1)
			else
				log("你已经是最新数据，无需更新！")
			end
		else
			icount = luci.sys.exec("cat /tmp/ssr-update." .. type .. " | wc -l")
			luci.sys.exec("cp -f /tmp/ssr-update." .. type .. " " .. file)
			if file2 then
				luci.sys.exec("cp -f /tmp/ssr-update." .. type .. " " .. file2)
			end
			if type == "gfw_data" or type == "ad_data" then
				luci.sys.call("/usr/share/shadowsocksr/gfw2ipset.sh")
			else
				luci.sys.call("/usr/share/shadowsocksr/chinaipset.sh " .. TMP_PATH .. "/china_ssr.txt")
			end
			if args then
				log(0, tonumber(icount) / Num)
			else
				log("更新成功！ 新的总记录数：" .. tostring(tonumber(icount) / Num))
			end
		end
	else
		if args then
			log(-1)
		else
			log("更新失败！")
		end
	end
	os.remove("/tmp/ssr-update." .. type)
end

if args then
	if args == "gfw_data" then
		update(uci:get_first("shadowsocksr", "global", "gfwlist_url"), "/etc/ssrplus/gfw_list.conf", args, TMP_DNSMASQ_PATH .. "/gfw_list.conf")
		os.exit(0)
	end
	if args == "ip_data" then
		update(uci:get_first("shadowsocksr", "global", "chnroute_url"), "/etc/ssrplus/china_ssr.txt", args, TMP_PATH .. "/china_ssr.txt")
		os.exit(0)
	end
	if args == "ad_data" then
		update(uci:get_first("shadowsocksr", "global", "adblock_url"), "/etc/ssrplus/ad.conf", args, TMP_DNSMASQ_PATH .. "/ad.conf")
		os.exit(0)
	end
	if args == "nfip_data" then
		update(uci:get_first("shadowsocksr", "global", "nfip_url"), "/etc/ssrplus/netflixip.list", args)
		os.exit(0)
	end
else
	log("正在更新【GFW列表】数据库")
	update(uci:get_first("shadowsocksr", "global", "gfwlist_url"), "/etc/ssrplus/gfw_list.conf", "gfw_data", TMP_DNSMASQ_PATH .. "/gfw_list.conf")
	log("正在更新【国内IP段】数据库")
	update(uci:get_first("shadowsocksr", "global", "chnroute_url"), "/etc/ssrplus/china_ssr.txt", "ip_data", TMP_PATH .. "/china_ssr.txt")
	if uci:get_first("shadowsocksr", "global", "adblock", "0") == "1" then
		log("正在更新【广告屏蔽】数据库")
		update(uci:get_first("shadowsocksr", "global", "adblock_url"), "/etc/ssrplus/ad.conf", "ad_data", TMP_DNSMASQ_PATH .. "/ad.conf")
	end
	-- log("正在更新【Netflix IP段】数据库")
	-- update(uci:get_first("shadowsocksr", "global", "nfip_url"), "/etc/ssrplus/netflixip.list", "nfip_data")
end
