# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=mosdns
PKG_VERSION:=810b2da
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/IrineSistiana/mosdns/tar.gz/$(PKG_VERSION)?
PKG_HASH:=skip

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_CONFIG_DEPENDS:= \
	CONFIG_MOSDNS_COMPRESS_GOPROXY \
	CONFIG_MOSDNS_COMPRESS_UPX

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/IrineSistiana/mosdns
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=main.version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/mosdns/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=A plug-in DNS forwarder/splitter
  URL:=https://github.com/IrineSistiana/mosdns
endef

define Package/mosdns
  $(call Package/mosdns/Default)
  DEPENDS:=$(GO_ARCH_DEPENDS)
endef

define Package/mosdns-geodata
  $(call Package/mosdns/Default)
  TITLE+= (geodata resources)
  DEPENDS:=mosdns
endef

define Package/mosdns/config
config MOSDNS_COMPRESS_GOPROXY
	bool "Compiling with GOPROXY proxy"
	default n

config MOSDNS_COMPRESS_UPX
	bool "Compress executable files with UPX"
	default y

select PACKAGE_mosdns-geodata
endef

ifeq ($(CONFIG_MOSDNS_COMPRESS_GOPROXY),y)
	export GO111MODULE=on
	export GOPROXY=https://goproxy.baidu.com
endif

GEOIP_VER:=202106030115
GEOIP_FILE:=geoip.dat.$(GEOIP_VER)

define Download/geoip
  URL:=https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download
  URL_FILE:=geoip.dat
  FILE:=$(GEOIP_FILE)
  HASH:=skip
endef

GEOSITE_VER:=20210531212831
GEOSITE_FILE:=dlc.dat.$(GEOSITE_VER)

define Download/geosite
  URL:=https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download
  URL_FILE:=geosite.dat
  FILE:=$(GEOSITE_FILE)
  HASH:=skip
endef

define Build/Prepare
	$(call Build/Prepare/Default)
ifneq ($(CONFIG_PACKAGE_mosdns-geodata),)
	$(call Download,geoip)
	$(call Download,geosite)
endif
endef

GO_PKG_TARGET_VARS:=$(filter-out CGO_ENABLED=%,$(GO_PKG_TARGET_VARS)) CGO_ENABLED=0

define Build/Compile
	$(call GoPackage/Build/Compile)
ifneq ($(CONFIG_MOSDNS_COMPRESS_UPX),)
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(GO_PKG_BUILD_BIN_DIR)/mosdns
endif
endef

define Package/mosdns/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/etc/mosdns
	$(INSTALL_DATA) ./files/config.yaml $(1)/etc/mosdns/config.yaml
endef

define Package/mosdns-geodata/install
	$(INSTALL_DIR) $(1)/etc/mosdns
	$(INSTALL_DATA) $(DL_DIR)/$(GEOIP_FILE) $(1)/etc/mosdns/geoip.dat
	$(INSTALL_DATA) $(DL_DIR)/$(GEOSITE_FILE) $(1)/etc/mosdns/geosite.dat
endef

$(eval $(call GoBinPackage,mosdns))
$(eval $(call BuildPackage,mosdns))
$(eval $(call BuildPackage,mosdns-geodata))