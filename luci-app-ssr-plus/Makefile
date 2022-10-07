include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ssr-plus
PKG_VERSION:=186
PKG_RELEASE:=6

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Xray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_SagerNet_Core \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Redsocks2 \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Trojan

LUCI_TITLE:=SS/SSR/V2Ray/Trojan/NaiveProxy/Socks5/Tun LuCI interface
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	@(PACKAGE_libustream-mbedtls||PACKAGE_libustream-openssl||PACKAGE_libustream-wolfssl) \
	+coreutils +coreutils-base64 +dns2socks +dns2tcp +dnsmasq-full +ipset +kmod-ipt-nat \
	+ip-full +iptables +iptables-mod-tproxy +lua +lua-neturl +libuci-lua +microsocks \
	+tcping +resolveip +shadowsocksr-libev-ssr-check +uclient-fetch

define Package/$(PKG_NAME)/config
	if PACKAGE_$(PKG_NAME)
		select PACKAGE_luci-lib-ipkg

		choice
			prompt "Shadowsocks Client Selection"
			default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client if aarch64
			default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client
			bool "None"

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client
			bool "Shadowsocks-libev"
			select PACKAGE_shadowsocks-libev-ss-local
			select PACKAGE_shadowsocks-libev-ss-redir

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
			bool "Shadowsocks-rust"
			depends on aarch64||arm||i386||mips||mipsel||x86_64
			depends on !(TARGET_x86_geode||TARGET_x86_legacy)
			select PACKAGE_shadowsocks-rust-sslocal
		endchoice

		choice
			prompt "Shadowsocks Server Selection"
			default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server if aarch64
			default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server if i386||x86_64||arm
			default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server
			bool "None"

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server
			bool "Shadowsocks-libev"
			select PACKAGE_shadowsocks-libev-ss-server

			config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server
			bool "Shadowsocks-rust"
			depends on aarch64||arm||i386||mips||mipsel||x86_64
			depends on !(TARGET_x86_geode||TARGET_x86_legacy)
			select PACKAGE_shadowsocks-rust-ssserver
		endchoice

		choice
			prompt "V2ray-core Selection"
			default PACKAGE_$(PKG_NAME)_INCLUDE_Xray if aarch64||arm||i386||x86_64
			default PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY

			config PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY
			bool "None"

			config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray
			bool "V2ray-core"
			select PACKAGE_curl
			select PACKAGE_v2ray-core

			config PACKAGE_$(PKG_NAME)_INCLUDE_Xray
			bool "Xray-core"
			select PACKAGE_curl
			select PACKAGE_xray-core

			config PACKAGE_$(PKG_NAME)_INCLUDE_SagerNet_Core
			bool "SagerNet-core (An enhanced edition of v2ray-core)"
			select PACKAGE_curl
			select PACKAGE_sagernet-core
		endchoice

		config PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun
			bool "Include Kcptun"
			select PACKAGE_kcptun-client
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria
			bool "Include Hysteria"
			select PACKAGE_hysteria
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks
			bool "Include IPT2Socks"
			select PACKAGE_ipt2socks
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
			bool "Include NaiveProxy"
			depends on !(arc||armeb||mips||mips64||powerpc||TARGET_gemini)
			select PACKAGE_naiveproxy
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_Redsocks2
			bool "Include Redsocks2"
			select PACKAGE_redsocks2
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs
			bool "Include Shadowsocks Simple Obfs Plugin"
			select PACKAGE_simple-obfs
			default y

		config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin
			bool "Include Shadowsocks V2ray Plugin"
			select PACKAGE_v2ray-plugin
			default n

		config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
			bool "Include ShadowsocksR Libev Client"
			select PACKAGE_shadowsocksr-libev-ssr-local
			select PACKAGE_shadowsocksr-libev-ssr-redir
			default y

		config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
			bool "Include ShadowsocksR Libev Server"
			select PACKAGE_shadowsocksr-libev-ssr-server
			default y if i386||x86_64||arm

		config PACKAGE_$(PKG_NAME)_INCLUDE_Trojan
			bool "Include Trojan"
			select PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks
			select PACKAGE_trojan
			default n
	endif
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/shadowsocksr
/etc/ssrplus/
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
