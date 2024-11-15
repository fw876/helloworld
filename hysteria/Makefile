# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria
PKG_VERSION:=2.6.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/apernet/hysteria/tar.gz/app/v$(PKG_VERSION)?
PKG_HASH:=c9d878ea81c78e71fcb07d47e3366cb4ae2ef5bce62f0ad81e58923db4995366
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-app-v$(PKG_VERSION)

PKG_LICENSE:=MIT
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/apernet/hysteria
GO_PKG_BUILD_PKG:=$(GO_PKG)/app/v2
GO_PKG_LDFLAGS_X = \
	$(GO_PKG)/app/v2/cmd.appVersion=v$(PKG_VERSION) \
	$(GO_PKG)/app/v2/cmd.appType=release \
	$(GO_PKG)/app/v2/cmd.appPlatform=$(GO_OS) \
	$(GO_PKG)/app/v2/cmd.appArch=$(GO_ARCH)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/hysteria
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A feature-packed network utility optimized for networks of poor quality
  URL:=https://github.com/apernet/hysteria
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/hysteria/description
  Hysteria is a feature-packed network utility optimized for networks
  of poor quality (e.g. satellite connections, congested public Wi-Fi,
  connecting from China to servers abroad) powered by a custom version
  of QUIC protocol.
endef

define Package/hysteria/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))

	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/app $(1)/usr/bin/hysteria
endef

$(eval $(call GoBinPackage,hysteria))
$(eval $(call BuildPackage,hysteria))
