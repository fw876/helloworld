#!/usr/bin/lua

local uci = require("uci")
local cursor = uci.cursor()

-- Function to get the DNSMasq configuration ID
local function get_dnsmasq_cfg_id()
    local id = nil
    cursor:foreach("dhcp", "dnsmasq", function(s)
        if not id then
            id = s[".name"] -- Get the internal ID of the first dnsmasq entry
        end
    end)
    return id
end

-- Get the DNSMasq configuration ID
local DEFAULT_DNSMASQ_CFGID = get_dnsmasq_cfg_id()
local DNSMASQ_CONF_DIR = nil
local TMP_DNSMASQ_PATH = nil

if DEFAULT_DNSMASQ_CFGID then
    local dnsmasq_conf_path = io.popen("grep -l '^conf-dir=' /tmp/etc/dnsmasq.conf." .. DEFAULT_DNSMASQ_CFGID):read("*a")
    dnsmasq_conf_path = dnsmasq_conf_path:gsub("%s+", "") -- Trim whitespace

    if dnsmasq_conf_path ~= "" then
        local dnsmasq_conf_dir = io.popen("grep '^conf-dir=' " .. dnsmasq_conf_path .. " | cut -d'=' -f2 | head -n 1"):read("*a")
        dnsmasq_conf_dir = dnsmasq_conf_dir:gsub("%s+", "") -- Trim whitespace

        if dnsmasq_conf_dir ~= "" then
            DNSMASQ_CONF_DIR = dnsmasq_conf_dir:gsub("/$", "") -- Remove trailing slash
            TMP_DNSMASQ_PATH = DNSMASQ_CONF_DIR .. "/dnsmasq-ssrplus.d"
        end
    end
end

-- Output variables in a format usable by shell scripts
io.write("DNSMASQ_CONF_DIR='", DNSMASQ_CONF_DIR or "", "'\n")
io.write("TMP_DNSMASQ_PATH='", TMP_DNSMASQ_PATH or "", "'\n")

