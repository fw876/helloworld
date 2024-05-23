# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2022 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=dns2tcp
PKG_VERSION:=1.1.1
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/zfl9/dns2tcp/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=35251fbe1645601086f21cdbd5a2f75471d812f99ed8017bb05158840456b43c

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16 gc-sections lto

include $(INCLUDE_DIR)/package.mk

define Package/dns2tcp
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=utility to convert dns query from udp to tcp
  URL:=https://github.com/zfl9/dns2tcp
endef

TARGET_CFLAGS+= $(FPIC)
MAKE_FLAGS+= \
	CFLAGS="-std=c99 $(TARGET_CFLAGS)" \
	EVCFLAGS="$(TARGET_CFLAGS)"

define Package/dns2tcp/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns2tcp $(1)/usr/bin/
endef

$(eval $(call BuildPackage,dns2tcp))
