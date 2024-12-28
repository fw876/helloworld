require "luci.util"
require "nixio.fs"
require "luci.sys"
require "luci.http"

f = SimpleForm("logview")
f.reset = false
f.submit = false
f:append(Template("shadowsocksr/log"))

-- 自定义 log 函数
function log(...)
    local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
    local f, err = io.open("/var/log/ssrplus.log", "a")
    if f and err == nil then
        f:write(result .. "\n")
        f:close()
    end
end

-- 创建备份与恢复表单
fb = SimpleForm('backup-restore')
fb.reset = false
fb.submit = false
s = fb:section(SimpleSection, translate("Backup and Restore"), translate("Backup or Restore Client and Server Configurations.") ..
                            "<br><font style='color:red'><b>" ..
                            translate("Note: Restoring configurations across different versions may cause compatibility issues.") ..
                            "</b></font>")
o = s:option(DummyValue, '', nil)
o.template = "shadowsocksr/backup_restore"

-- 定义备份目标文件和目录
local backup_targets = {
    files = {
        "/etc/config/shadowsocksr"
    },
    dirs = {
        "/etc/ssrplus"
    }
}

local file_path = '/tmp/shadowsocksr_upload.tar.gz'
local temp_dir = '/tmp/shadowsocksr_bak'
local fd

-- 处理文件上传
luci.http.setfilehandler(function(meta, chunk, eof)
    if not fd and meta and meta.name == "ulfile" and chunk then
        -- 初始化上传处理
        luci.sys.call("rm -rf " .. temp_dir)
        nixio.fs.remove(file_path)
        fd = nixio.open(file_path, "w")
        luci.sys.call("echo '' > /var/log/ssrplus.log")
    end

    if fd and chunk then
        fd:write(chunk)
    end

    if eof and fd then
        fd:close()
        fd = nil
        if nixio.fs.access(file_path) then
            log(" * shadowsocksr 配置文件上传成功…")  -- 使用自定义的 log 函数
            luci.sys.call("mkdir -p " .. temp_dir)

            if luci.sys.call("tar -xzf " .. file_path .. " -C " .. temp_dir) == 0 then
                -- 处理文件还原
                for _, target in ipairs(backup_targets.files) do
                    local temp_file = temp_dir .. target
                    if nixio.fs.access(temp_file) then
                        luci.sys.call(string.format("cp -f '%s' '%s'", temp_file, target))
                        log(" * 文件 " .. target .. " 还原成功…")  -- 使用自定义的 log 函数
                    end
                end

                -- 处理目录还原
                for _, target in ipairs(backup_targets.dirs) do
                    local temp_dir_path = temp_dir .. target
                    if nixio.fs.access(temp_dir_path) then
                        luci.sys.call(string.format("cp -rf '%s'/* '%s/'", temp_dir_path, target))
                        log(" * 目录 " .. target .. " 还原成功…")  -- 使用自定义的 log 函数
                    end
                end

                log(" * shadowsocksr 配置还原成功…")  -- 使用自定义的 log 函数
                log(" * 重启 shadowsocksr 服务中…\n")  -- 使用自定义的 log 函数
                luci.sys.call('/etc/init.d/shadowsocksr restart > /dev/null 2>&1 &')
            else
                log(" * shadowsocksr 配置文件解压失败，请重试！")  -- 使用自定义的 log 函数
            end
        else
            log(" * shadowsocksr 配置文件上传失败，请重试！")  -- 使用自定义的 log 函数
        end

        -- 清理临时文件
        luci.sys.call("rm -rf " .. temp_dir)
        nixio.fs.remove(file_path)
    end
end)

return f, fb
