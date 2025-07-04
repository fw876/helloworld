# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=shadow-tls
PKG_VERSION:=0.2.25
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ihciah/shadow-tls/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=1d1d436734823ba0302de6e91883ed892ea710769c722a139990194ff5837224

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/shadow-tls
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=A proxy to expose real tls handshake to the firewall
  URL:=https://github.com/ihciah/shadow-tls
  DEPENDS:=@(aarch64||arm||x86_64)
endef

define Package/shadow-tls/description
  A proxy to expose real tls handshake to the firewall.

  It works like trojan but it does not require signing certificate.
  The firewall will see real tls handshake with valid certificate
  that you choose.
endef

$(eval $(call RustBinPackage,shadow-tls))
$(eval $(call BuildPackage,shadow-tls))
