include $(TOPDIR)/rules.mk

LUCI_TITLE:=luci-app-ssr-plus
LUCI_PKGARCH:=all
PKG_NAME:=luci-app-ssr-plus
PKG_VERSION:=190
PKG_RELEASE:=3

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Xray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS_RUST \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_DNS2TCP \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_DNSPROXY \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Tuic_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun \
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

LUCI_TITLE:=SS/SSR/V2Ray/Trojan/NaiveProxy/Tuic/ShadowTLS/Hysteria/Socks5/Tun LuCI interface
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	+coreutils +coreutils-base64 +dns2tcp +dnsmasq-full \
	+jq +ip-full +lua +lua-neturl +libuci-lua +microsocks \
	+tcping +resolveip +shadowsocksr-libev-ssr-check +curl +nping \
	+PACKAGE_$(PKG_NAME)_INCLUDE_V2ray:curl \
	+PACKAGE_$(PKG_NAME)_INCLUDE_V2ray:v2ray-core \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Xray:curl \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Xray:xray-core \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG:chinadns-ng \
	+PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS:dns2socks \
	+PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS_RUST:dns2socks-rust \
	+PACKAGE_$(PKG_NAME)_INCLUDE_DNSPROXY:dnsproxy \
	+PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS:mosdns \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria:hysteria \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Tuic_Client:tuic-client \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS:shadow-tls \
	+PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks:ipt2socks \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun:kcptun-client \
	+PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy:naiveproxy \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Redsocks2:redsocks2 \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client:shadowsocks-libev-ss-local \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client:shadowsocks-libev-ss-redir \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server:shadowsocks-libev-ss-server \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client:shadowsocks-rust-sslocal \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server:shadowsocks-rust-ssserver \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs:simple-obfs-client \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin:v2ray-plugin \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client:shadowsocksr-libev-ssr-local \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client:shadowsocksr-libev-ssr-redir \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server:shadowsocksr-libev-ssr-server \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Trojan:trojan


define Package/$(PKG_NAME)/config
select PACKAGE_luci-lua-runtime if PACKAGE_$(PKG_NAME)

choice
	prompt "Transparent Proxy Backend"
	default PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy if ! PACKAGE_firewall4
	default PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy if PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy
	bool "Iptables Transparent Proxy"
	select PACKAGE_dnsmasq_full_ipset
	select PACKAGE_ipset
	select PACKAGE_iptables
	select PACKAGE_iptables-zz-legacy
	select PACKAGE_iptables-mod-conntrack-extra
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
	select PACKAGE_kmod-ipt-nat

config PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy
	bool "Nftables Transparent Proxy"
	select PACKAGE_dnsmasq_full_nftset
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
endchoice

choice
	prompt "Shadowsocks Client Selection"
	default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client if aarch64 || x86_64
	default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client
	bool "None"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client
	bool "Shadowsocks-libev"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	bool "Shadowsocks-rust"
	depends on aarch64||arm||i386||mips||mipsel||x86_64
	depends on !(TARGET_x86_geode||TARGET_x86_legacy)
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

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server
	bool "Shadowsocks-rust"
	depends on aarch64||arm||i386||mips||mipsel||x86_64
	depends on !(TARGET_x86_geode||TARGET_x86_legacy)
endchoice

choice
	prompt "V2ray-core Selection"
	default PACKAGE_$(PKG_NAME)_INCLUDE_Xray if aarch64||arm||i386||x86_64
	default PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY

	config PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY
	bool "None"

	config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray
	bool "V2ray-core"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Xray
	bool "Xray-core"
endchoice

config PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	bool "Include ChinaDNS-NG"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS
	bool "Include DNS2socks"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_DNS2SOCKS_RUST
	bool "Include DNS2socks-Rust"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_DNSPROXY
	bool "Include DNSproxy"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS
	bool "Include MosDNS"
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria
	bool "Include Hysteria"
	select PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Tuic_Client
	bool "Include Tuic-Client"
	select PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	select PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks
	depends on aarch64||arm||i386||x86_64
	depends on !(TARGET_x86_geode||TARGET_x86_legacy)
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS
	bool "Include Shadow-TLS"
	select PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	select PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	depends on aarch64||arm||x86_64
	depends on !(TARGET_x86_geode||TARGET_x86_legacy)
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks
	bool "Include IPT2Socks"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun
	bool "Include Kcptun"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
	bool "Include NaiveProxy"
	depends on !(arc||armeb||mips||mips64||powerpc||TARGET_gemini)
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Redsocks2
	bool "Include Redsocks2"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs
	bool "Include Shadowsocks Simple Obfs Plugin"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin
	bool "Include Shadowsocks V2ray Plugin"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
	bool "Include ShadowsocksR Libev Client"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server"
	default y if i386||x86_64||arm

config PACKAGE_$(PKG_NAME)_INCLUDE_Trojan
	bool "Include Trojan"
	select PACKAGE_$(PKG_NAME)_INCLUDE_IPT2Socks
	default n

endef


define Package/$(PKG_NAME)/conffiles
/etc/config/shadowsocksr
/etc/ssrplus/
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
