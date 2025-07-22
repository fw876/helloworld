# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=tcping
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Lienol/tcping.git
PKG_SOURCE_DATE:=2020-07-04
PKG_SOURCE_VERSION:=db9101834732dac9aaa59dbb7fb9c74612dbf723
PKG_MIRROR_HASH:=d30c1bb624afd7e4f0596d5c58d393937f6c0102f0b336c604a24a35df5173b7

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=license.txt

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tcping
  SECTION:=net
  CATEGORY:=Network
  TITLE:=tcping measures the latency of a tcp-connection
  URL:=https://github.com/jlyo/tcping
endef

define Package/tcping/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tcping $(1)/usr/bin/
endef

$(eval $(call BuildPackage,tcping))
