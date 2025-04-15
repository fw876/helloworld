# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=redsocks2
PKG_VERSION:=0.71
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/semigodking/redsocks.git
PKG_SOURCE_DATE:=2024-12-05
PKG_SOURCE_VERSION:=5d2db3e15543854da30e88af40748dfe63af2c28
PKG_MIRROR_HASH:=5c06c3646434c498fe22379cb2085269d1e384e1a2db2941ca844a0a5da1f0dc

PKG_MAINTAINER:=semigodking <semigodking@gmail.com>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/redsocks2
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Redirect any TCP connection to a SOCKS or HTTPS proxy server
  URL:=https://github.com/semigodking/redsocks
  DEPENDS:=+libevent2 +libopenssl
endef

define Package/redsocks2/description
This is a modified version of original redsocks. \
The name is changed to be REDSOCKS2 since this release to distinguish with original redsocks. \
This variant is useful for anti-GFW (Great Fire Wall).
endef

define Build/Compile
	$(call Build/Compile/Default,DISABLE_SHADOWSOCKS=true)
endef

define Package/redsocks2/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/redsocks2 $(1)/usr/sbin
endef

$(eval $(call BuildPackage,redsocks2))
