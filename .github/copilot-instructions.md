# OpenWrt helloworld 项目 AI 编码助手指导

本项目是一个针对 OpenWrt 的代理工具包集合，主要包含 ShadowSocks、V2Ray、Xray、Trojan 等各种网络代理工具的 OpenWrt 包。

## 项目架构概览

### 核心组件分类
- **LuCI 应用**: `luci-app-ssr-plus/` - 统一的 Web 管理界面
- **代理工具**: `shadowsocks-*`, `v2ray-*`, `xray-*`, `trojan/` 等目录
- **DNS 工具**: `chinadns-ng/`, `dns2socks/`, `mosdns/` 等
- **辅助工具**: `tcping/`, `microsocks/`, `redsocks2/` 等

### 关键架构决策
- 每个工具都是独立的 OpenWrt 包，拥有自己的 Makefile 和构建配置
- LuCI 应用通过 UCI 配置系统统一管理所有代理工具
- 支持多架构编译（arm, mips, x86_64 等），通过 CI/CD 自动测试
- 使用条件编译机制，用户可选择性包含所需组件

## OpenWrt 包开发约定

### Makefile 模式
```makefile
include $(TOPDIR)/rules.mk

PKG_NAME:=工具名
PKG_VERSION:=版本号
PKG_RELEASE:=构建版本

# 语言特定的构建依赖
PKG_BUILD_DEPENDS:=golang/host  # Go 项目
PKG_BUILD_DEPENDS:=rust/host    # Rust 项目
PKG_BUILD_DEPENDS:=openssl      # C/C++ 项目

# 包含相应的构建框架
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk  # Go
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk      # Rust
```

### 包依赖管理
- **运行时依赖**: `DEPENDS:=+ca-bundle +libstdcpp` 
- **架构限制**: `depends on !(arc||armeb||mips)` 排除特定架构
- **条件依赖**: 通过 `CONFIG_PACKAGE_*` 实现选择性依赖

### 版本管理约定
- 使用上游项目的语义化版本号
- `PKG_RELEASE` 用于本项目的修订版本
- 通过 `PKG_SOURCE_URL` 和 `PKG_HASH` 确保构建可重现性

## LuCI 应用集成模式

### 文件结构约定
```
luci-app-ssr-plus/
├── luasrc/
│   ├── controller/shadowsocksr.lua    # 路由控制器
│   ├── model/cbi/shadowsocksr/        # 配置界面模型
│   └── view/shadowsocksr/             # 自定义视图模板
├── root/
│   ├── etc/init.d/shadowsocksr        # 系统服务脚本
│   ├── etc/config/shadowsocksr        # UCI 配置模板
│   └── usr/share/shadowsocksr/        # 业务逻辑脚本
└── po/                                # 国际化文件
```

### UCI 配置模式
- 配置文件: `/etc/config/shadowsocksr`
- 通过 `uci get/set` 命令访问配置
- LuCI 界面自动与 UCI 配置同步
- 配置更改触发服务重启: `/etc/init.d/shadowsocksr restart`

### 多协议支持模式
```lua
-- 动态检测可用的代理工具
local function is_finded(e)
    return luci.sys.exec(string.format('type -t -p "%s" 2>/dev/null', e)) ~= ""
end

-- 根据检测结果动态生成选项
if is_finded("xray") or is_finded("v2ray") then
    o:value("v2ray", translate("V2Ray/XRay"))
end
```

## 开发工作流程

### 构建和测试
```bash
# 克隆项目作为 OpenWrt feed
git clone https://github.com/fw876/helloworld.git package/helloworld

# 或作为 git submodule
git submodule add https://github.com/fw876/helloworld.git package/helloworld

# 构建特定包
make package/helloworld/luci-app-ssr-plus/compile V=s
```

### 多架构支持
- CI 自动测试 7 种主要架构（arm, mips, x86 等）
- 每个 Makefile 需声明架构兼容性
- 使用 `PKG_BUILD_PARALLEL:=1` 启用并行构建

### 配置系统集成
- 通过 `PKG_CONFIG_DEPENDS` 声明配置依赖关系
- LuCI 应用的配置选项影响包的编译行为
- 使用 `choice` 和 `config` 块实现互斥选项

## 关键集成点

### 服务管理
- 所有服务通过 `/etc/init.d/shadowsocksr` 统一管理
- 支持 `start`, `stop`, `restart`, `status` 等标准操作
- 使用 `SERVICE_DAEMONIZE=1` 实现后台运行

### 配置生成
- `/usr/share/shadowsocksr/gen_config.lua` 负责生成各代理工具的原生配置
- 支持 JSON 配置格式的自动转换
- 实现了配置模板系统，支持动态参数替换

### 订阅和更新
- `/usr/share/shadowsocksr/subscribe.lua` 处理节点订阅
- 支持多种订阅链接格式（ss://, ssr://, vmess:// 等）
- 自动解析和转换节点配置格式

## 调试和日志
- 主日志文件: `/var/log/ssrplus.log`
- 使用 `uci show shadowsocksr` 查看当前配置
- 通过 LuCI 界面的"状态"页面监控服务运行状态

## 注意事项
- 修改 LuCI 文件后需要清除浏览器缓存
- UCI 配置更改需要 `uci commit` 才能生效
- 新增代理工具需要同时更新 LuCI 界面和服务脚本
- 多语言支持需要更新 `po/` 目录下的翻译文件