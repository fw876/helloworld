include $(TOPDIR)/rules.mk

PKG_NAME:=Xray-core
PKG_VERSION:=1.5.4
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/XTLS/xray-core/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=af9b9b5b0a2d4f055d19f3580d1c2d3141bbaab9dd7824428c12ae0ced5f511e

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MPL-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_CONFIG_DEPENDS:= \
	CONFIG_XRAY_CORE_COMPRESS_GOPROXY \
	CONFIG_XRAY_CORE_COMPRESS_UPX \

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/xtls/xray-core
GO_PKG_BUILD_PKG:=github.com/xtls/xray-core/main
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/core.build=OpenWrt \
	$(GO_PKG)/core.version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/xray-core
  TITLE:=A platform for building proxies to bypass network restrictions
  SECTION:=net
  CATEGORY:=Network
  URL:=https://xtls.github.io
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/xray-core/description
  Xray, Penetrates Everything. It helps you to build your own computer network.
  It secures your network connections and thus protects your privacy.
endef

define Package/xray-core/config
menu "Xray-core Configuration"
	depends on PACKAGE_xray-core

config XRAY_CORE_COMPRESS_GOPROXY
	bool "Compiling with GOPROXY proxy"
	default n

config XRAY_CORE_COMPRESS_UPX
	bool "Compress executable files with UPX"
	depends on !mips64
	default n
endmenu
endef

ifneq ($(CONFIG_XRAY_CORE_COMPRESS_GOPROXY),)
	export GO111MODULE=on
	export GOPROXY=https://goproxy.bj.bcebos.com
endif

define Build/Compile
	$(call GoPackage/Build/Compile)
ifneq ($(CONFIG_XRAY_CORE_COMPRESS_UPX),)
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(GO_PKG_BUILD_BIN_DIR)/main
endif
endef

define Package/xray-core/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/main $(1)/usr/bin/xray
endef

$(eval $(call BuildPackage,xray-core))
