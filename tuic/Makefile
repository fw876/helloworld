# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=tuic-client
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_HEADER:=tuic-client-$(PKG_VERSION)
PKG_SOURCE_BODY:=unknown-linux-musl
#PKG_SOURCE_FOOTER:=tar.xz
PKG_SOURCE_URL:=https://https://github.com/EAimTY/tuic/releases/download/$(PKG_SOURCE_HEADER)-$(PKG_VERSION)/

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-aarch64-$(PKG_SOURCE_BODY)
  PKG_HASH:=
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER)-arm-$(PKG_SOURCE_BODY)eabi
    PKG_HASH:=5ec0a5708bc4d1c984b48e70cc96642bc89ade19ee9b299af1f4522fd421561e
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER)-arm-$(PKG_SOURCE_BODY)eabihf
    PKG_HASH:=949f60a860dad40170bc70889af7a826f22b6fbaef55095fe8ef413cdd658b4a
  endif
else ifeq ($(ARCH),i686)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-i686-$(PKG_SOURCE_BODY)
  PKG_HASH:=5b5e98f593493850dc4a29517f537136dc0fd62ae56ba958bbefcc4ba9b467dd
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-x86_64-$(PKG_SOURCE_BODY)
  PKG_HASH:=6d1d73fb94bac7d15d360d9e1cbd9d6787faa20e7881ee41b7c444e7b520194a
# Set the default value to make OpenWrt Package Checker happy
else
  PKG_SOURCE:=dummy
  PKG_HASH:=dummy
endif

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

TAR_CMD:=$(HOST_TAR) -C $(PKG_BUILD_DIR) $(TAR_OPTIONS)

define Package/tuic-client/Default
  define Package/tuic-client-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=tuic-client $(1)
    URL:=https://github.com/EAimTY/tuic/
    DEPENDS:=@USE_MUSL @(aarch64||arm||i686||x86_64) @!(TARGET_x86_geode||TARGET_x86_legacy)
  endef

  define Package/tuic-client-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_BUILD_DIR)/$(1) $$(1)/usr/bin
  endef
endef

TUIC_COMPONENTS:=tuic-client
define tuic-client/templates
  $(foreach component,$(TUIC_COMPONENTS),
    $(call Package/tuic-client/Default,$(component))
  )
endef
$(eval $(call tuic-client/templates))

define Build/Compile
endef

$(foreach component,$(TUIC_COMPONENTS), \
  $(eval $(call BuildPackage,tuic-client-$(component))) \
)
