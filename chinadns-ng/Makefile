# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=2024.07.21
PKG_RELEASE:=1

ifeq ($(ARCH),aarch64)
  ifeq ($(BOARD),rockchip)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=1a65fadc48956231eba439efd9ae914f6e5eb0f5d257a34cd8c6b0d5734ade57
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=9414c8f237b8a919d411fb38a7d2aa83c7617ae441695af54ea84feb22b0639c
  endif
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v5t+soft_float@fast+lto
    PKG_HASH:=3d1a89bdc413f6922df43f2c1a18f199e83ec7e5d6d68961a10229a73188b07a
  else ifneq ($(filter $(ARM_CPU_FEATURES),vfp vfpv2),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v6+soft_float@fast+lto
    PKG_HASH:=d9095d72dba4018c21ab794c81e467011eee8b3582822a3fa45b803bfdf0d4fa
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabihf@generic+v7a@fast+lto
    PKG_HASH:=61fff30848f687d93e58bb91029252818d76e0980d4d32fd2bf6d67dfa51cd4f
  endif
else ifeq ($(ARCH),i386)
  ifneq ($(CONFIG_TARGET_x86_geode)$(CONFIG_TARGET_x86_legacy),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@i686@fast+lto
    PKG_HASH:=8fd1f8cc1ee5f24a10a45367d3444a7af0618f01bf5ea1d14c8bfac856062a23
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@pentium4@fast+lto
    PKG_HASH:=15983518255abc1849b13352763112442388519109625a9fcd92f50e05831b1c
  endif
else ifeq ($(ARCH),mips)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips-linux-musl@mips32+soft_float@fast+lto
  PKG_HASH:=1b804d4c450d10cb6f91ac0656121bf9fd3e499f15ea569770b8d5523d5290c2
else ifeq ($(ARCH),mipsel)
  ifeq ($(CONFIG_HAS_FPU),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32+soft_float@fast+lto
    PKG_HASH:=82d07d148e2c20d4247df7baa0421f1c365954c0953e0e0fbe76e1cd78d1f1b2
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32@fast+lto
    PKG_HASH:=4a0f66796fbde9c276345ca5e5d4995ce28fef9d54c9538cd931fc2e03de78dd
  endif
else ifeq ($(ARCH),x86_64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@x86_64-linux-musl@x86_64@fast+lto
  PKG_HASH:=8d600757acf4fcb6250aef6ba5bf19d9a2182a188e900d1201381ab0a52a5463
else
  PKG_ARCH:=dummy
  PKG_HASH:=dummy
endif

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(ARCH_PACKAGES)
PKG_SOURCE_URL:=https://github.com/zfl9/chinadns-ng/releases/download/$(PKG_VERSION)/$(PKG_ARCH)?
UNPACK_CMD=$(CP) $(DL_DIR)/$(PKG_SOURCE) $(PKG_BUILD_DIR)/$(PKG_NAME)

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

include $(INCLUDE_DIR)/package.mk

define Package/chinadns-ng
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=ChinaDNS next generation, refactoring with epoll and ipset.
  URL:=https://github.com/zfl9/chinadns-ng
  DEPENDS:=@(aarch64||arm||i386||mips||mipsel||x86_64)
endef

define Build/Compile
endef

define Package/chinadns-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin/chinadns-ng
endef

$(eval $(call BuildPackage,chinadns-ng))
