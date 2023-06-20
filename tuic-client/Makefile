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
PKG_SOURCE_URL:=https://github.com/EAimTY/tuic/releases/download/$(PKG_SOURCE_HEADER)/$(PKG_SOURCE_HEADER)-$(PKG_SOURCE_BODY)

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-aarch64-$(PKG_SOURCE_BODY)
  PKG_HASH:=29eaaf3bc05115acc7453ac26bacf9aff65211b1e8ca7f771b818248bec8601
else ifeq ($ARCH),arm)
        # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER)-armv7-$(PKG_SOURCE_BODY)eabi
    PKG_HASH:=33a83ab05dc1a598552bf1f27114502b12c94b6e5333c6ac2def3739c00a4daf
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER)-armv7-$(PKG_SOURCE_BODY)eabihf
    PKG_HASH:=e2cc1d81ac376ff2a94976e78c861f5cd21ad809ff5b587ae967e2a63e4c35e4
  endif
else ifeq ($(ARCH),i686)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-i686-$(PKG_SOURCE_BODY)
  PKG_HASH:=67d930b4381a8848bf98acbccb538c73b72ca9dde0aed3705f73e62a9922f758
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER)-x86_64-$(PKG_SOURCE_BODY)
  PKG_HASH:=180c562691247a7feddf553706bc8fd5b5b9de3027154f94a767ea907a45e2de
# Set the default value to make OpenWrt Package Checker happy
else
  PKG_SOURCE:=dummy
  PKG_HASH:=dummy
endif

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

#TAR_CMD:=$(HOST_TAR) -C $(PKG_BUILD_DIR) $(TAR_OPTIONS)

define Package/tuic-client
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=Delicately-TUICed 0-RTT proxy protocol
    URL:=https://github.com/EAimTY/tuic/
    DEPENDS:=@USE_MUSL @(aarch64||arm||i686||x86_64) @!(TARGET_x86_geode||TARGET_x86_legacy)
endef

define Package/tuic-client/description
        TUIC is a proxy protocol focusing on minimize the additional handshake
         latency caused by relaying as much as possible, as well as keeping 
        the protocol itself being simple and easy to implement.
        TUIC is originally designed to be used on top of the QUIC protocol, 
        but you can use it with any other protocol, e.g. TCP, in theory
endef

  define Package/tuic-client/install
        $(INSTALL_DIR) $(1)/usr/bin
        $(INSTALL_BIN) $(PKG_BUILD_DIR)/ $(1)/usr/bin/tuic-client
  endef

define Build/Compile
endef

 $(eval $(call BuildPackage,tuic-client))
