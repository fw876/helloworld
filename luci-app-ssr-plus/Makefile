include $(TOPDIR)/rules.mk

LUCI_TITLE:=luci-app-ssr-plus
LUCI_PKGARCH:=all
PKG_NAME:=luci-app-ssr-plus
PKG_VERSION:=196
PKG_RELEASE:=1

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Xray \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_DNS2TCP \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Http_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Mihomo \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server

LUCI_TITLE:=SS/SSR/V2Ray/Trojan/NaiveProxy/Tuic/ShadowTLS/Hysteria/Socks5/Clash LuCI interface
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	+libuci-lua +lua +luci-compat +coreutils +coreutils-base64 +dns2tcp +dnsmasq-full \
	+jq +ip-full +lua-neturl +libuci-lua +microsocks +ipt2socks +lyaml \
	+resolveip +curl +nping +unzip +xz-utils \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG:chinadns-ng \
	+PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS:mosdns \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS:shadow-tls \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun:kcptun-client \
	+PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy:naiveproxy \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client:shadowsocks-rust-sslocal \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server:shadowsocks-rust-ssserver \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs:simple-obfs-client \
	+PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin:v2ray-plugin \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client:shadowsocksr-libev-ssr-local \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client:shadowsocksr-libev-ssr-redir \
	+PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server:shadowsocksr-libev-ssr-server


define Package/$(PKG_NAME)/config

choice
	prompt "Transparent Proxy Backend"
	default PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy if ! PACKAGE_firewall4
	default PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy if PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy
	bool "Iptables Transparent Proxy"
	depends on !PACKAGE_firewall4
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
	depends on PACKAGE_firewall4
	select PACKAGE_dnsmasq_full_nftset
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
endchoice

choice
	prompt "Shadowsocks Client Selection"
	default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Client
	bool "None"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	bool "Shadowsocks Rust"
endchoice

choice
	prompt "Shadowsocks Server Selection"
	default PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_NONE_Server
	bool "None"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server
	bool "Shadowsocks Rust"
endchoice

choice
	prompt "V2ray-core Selection"
	default PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY

	config PACKAGE_$(PKG_NAME)_INCLUDE_NONE_V2RAY
	bool "None"

	config PACKAGE_$(PKG_NAME)_INCLUDE_Xray
	bool "Xray-core"
	select PACKAGE_xray-core
	select PACKAGE_coreutils-timeout
endchoice

config PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	bool "Include ChinaDNS-NG"
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_MosDNS
	bool "Include MosDNS"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Http_Proxy
	bool "Include HTTP(S) Proxy Server"
	select PACKAGE_3proxy
	default y if (aarch64||arm||i386||loongarch64||riscv64||x86_64)

config PACKAGE_$(PKG_NAME)_INCLUDE_Mihomo
	bool "Include Mihomo (Clash Support)"
	select PACKAGE_mihomo
	select PACKAGE_v2ray-geoip
	depends on aarch64||arm||i386||loongarch64||riscv64||x86_64
	default y if aarch64||arm||i386||loongarch64||riscv64||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_GeoData
	bool "Include GeoData (GeoIP and GeoSite)"
	select PACKAGE_v2ray-geoip
	select PACKAGE_v2ray-geosite
	default y if i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadow_TLS
	bool "Include Shadow-TLS"
	select PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	select PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	depends on aarch64||arm||x86_64
	depends on !(TARGET_x86_geode||TARGET_x86_legacy)
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun
	bool "Include Kcptun"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
	bool "Include NaiveProxy"
	depends on !(arc||armeb||mips||mips64||powerpc||TARGET_gemini)
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Simple_Obfs
	bool "Include Shadowsocks Simple Obfs Plugin"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_V2ray_Plugin
	bool "Include Shadowsocks V2ray Plugin"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
	bool "Include ShadowsocksR Libev Client"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server"
	default n

endef


define Package/$(PKG_NAME)/conffiles
/etc/config/shadowsocksr
/etc/ssrplus/
endef

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/install
 ifneq ($(wildcard ${CURDIR}/luasrc),)
	$(INSTALL_DIR) $(1)$(LUCI_LIBRARYDIR)
	cp -pR $(PKG_BUILD_DIR)/luasrc/* $(1)$(LUCI_LIBRARYDIR)/
	$(FIND) $(1)$(LUCI_LIBRARYDIR)/ -type f -name '*.luadoc' | $(XARGS) rm
	$(if $(CONFIG_LUCI_SRCDIET),$(call SrcDiet,$(1)$(LUCI_LIBRARYDIR)/),true)
	$(call SubstituteVersion,$(1)$(LUCI_LIBRARYDIR)/)
 endif
 ifneq ($(wildcard ${CURDIR}/ucode),)
	  $(INSTALL_DIR) $(1)$(UCODE_LIBRARYDIR)
	  cp -pR $(PKG_BUILD_DIR)/ucode/* $(1)$(UCODE_LIBRARYDIR)/
	  $(call SubstituteVersion,$(1)$(UCODE_LIBRARYDIR)/)
 endif
 ifneq ($(wildcard ${CURDIR}/htdocs),)
	$(INSTALL_DIR) $(1)$(HTDOCS)
	cp -pR $(PKG_BUILD_DIR)/htdocs/* $(1)$(HTDOCS)/
	$(if $(CONFIG_LUCI_JSMIN),$(call JsMin,$(1)$(HTDOCS)/),true)
	$(if $(CONFIG_LUCI_CSSTIDY),$(call CssTidy,$(1)$(HTDOCS)/),true)
 endif
 ifneq ($(wildcard ${CURDIR}/root),)
	$(INSTALL_DIR) $(1)/
	cp -pR $(PKG_BUILD_DIR)/root/* $(1)/
 endif
 ifneq ($(wildcard ${CURDIR}/src),)
	$(call Build/Install/Default)
	$(CP) $(PKG_INSTALL_DIR)/* $(1)/
 endif
	if [ -d "$(1)/usr/bin" ]; then \
		chmod 0755 "$(1)/usr/bin/ssr-monitor" 2>/dev/null || true; \
		chmod 0755 "$(1)/usr/bin/ssr-rules" 2>/dev/null || true; \
		chmod 0755 "$(1)/usr/bin/ssr-switch" 2>/dev/null || true; \
	fi
	if [ -f "$(1)/etc/hotplug.d/iface/99-ssrplus-pppoe" ]; then \
		chmod 0755 "$(1)/etc/hotplug.d/iface/99-ssrplus-pppoe" 2>/dev/null || true; \
	fi
endef

# call BuildPackage - OpenWrt buildroot signature
