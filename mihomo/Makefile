include $(TOPDIR)/rules.mk

PKG_NAME:=mihomo
PKG_VERSION:=1.19.32
PKG_RELEASE:=4

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/MetaCubeX/mihomo.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_MIRROR_HASH:=0194b7039e6ff1143c7b80dd70d3a06976f60ff9f40802111d15a93da06c8a95

PKG_LICENSE:=GPL3.0+
PKG_MAINTAINER:=Joseph Mory <morytyann@gmail.com>

PKG_BUILD_DEPENDS:=golang/host upx/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

PKG_BUILD_VERSION:=v$(PKG_VERSION)
PKG_BUILD_TIME:=$(shell date -u -Iseconds)

GO_PKG:=github.com/metacubex/mihomo
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=$(GO_PKG)/constant.Version=$(PKG_BUILD_VERSION) $(GO_PKG)/constant.BuildTime=$(PKG_BUILD_TIME)
GO_PKG_TAGS:=with_gvisor
GO_PKG_INSTALL_BIN_PATH:=/usr/libexec

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# Generate a private overlay with the exact Go toolchain used for this package.
# Runtime DT detection restricts hardware use to AN7581 without ARM AES.
ifeq ($(GO_ARCH),arm64)
  define Build/Compile
	$(GO_PKG_VARS) python3 $(PKG_BUILD_DIR)/tools/eip93/overlay.py --go go --out $(PKG_BUILD_DIR)/.eip93-overlay
	$(call GoPackage/Build/Compile,-overlay=$(PKG_BUILD_DIR)/.eip93-overlay/overlay.json)
  endef
endif

# Compress once per build, not once per package/rootfs installation.
# Keep Go's output intact and let the .built stamp guard the packed copy.
define Build/Install
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/.upx
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/mihomo $(PKG_BUILD_DIR)/.upx/mihomo
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(PKG_BUILD_DIR)/.upx/mihomo
endef

# Go's -s -w flags strip the binary before UPX; do not strip it again.
RSTRIP:=:

define Package/mihomo
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A rule based proxy in Go.
  URL:=https://wiki.metacubex.one
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
  ALTERNATIVES:=\
    300:/usr/bin/mihomo:/usr/libexec/mihomo
endef

define Package/mihomo/description
  Mihomo is a rule based proxy in Go.
endef

define Package/mihomo/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/.upx/mihomo $(1)/usr/libexec/mihomo
endef

define Build/Prepare
	$(Build/Prepare/Default)
	$(RM) -r $(PKG_BUILD_DIR)/rules/logic_test
endef

$(eval $(call GoBinPackage,mihomo))
$(eval $(call BuildPackage,mihomo))
