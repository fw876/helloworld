# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=2024.12.22
PKG_RELEASE:=1

ifeq ($(ARCH),aarch64)
  ifeq ($(BOARD),rockchip)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=2e17092170abf989c5333a021cdb6789059069a24cf06856a5805336b99fd1a7
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=a4d58dc9f9a6d49133f008b4f3941486396934ae2b3f9ebf9b8bf5e3d1cf656b
  endif
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v5t+soft_float@fast+lto
    PKG_HASH:=b6ac722b289a62eb02cda5c2c17cc48bb977ab77cce3bf7459841542dfe4dc29
  else ifneq ($(filter $(ARM_CPU_FEATURES),vfp vfpv2),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v6+soft_float@fast+lto
    PKG_HASH:=e0af25ed7516b4e2bffd8cfb22b45cc1dbdeb47bce02f6495ca8ea1c407fd75c
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabihf@generic+v7a@fast+lto
    PKG_HASH:=e7a42ed517c73c56bdd7ddf52b5e1263b7aea488ceb82c303278fc7760353b90
  endif
else ifeq ($(ARCH),mips)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips-linux-musl@mips32+soft_float@fast+lto
  PKG_HASH:=926811e55d46ed275f678b62d9fe67e35a053243475306c391b1c3c6a61d9710
else ifeq ($(ARCH),mipsel)
  ifeq ($(CONFIG_HAS_FPU),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32+soft_float@fast+lto
    PKG_HASH:=071ed28e06f9306b4f25c2b9a9bb83ddcfb4dde0cc08d0b232efd772f8a8792a
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32@fast+lto
    PKG_HASH:=3fc760ff12e3455bd6cbf3d65c2f0f0a8eb806e451bdadcfb6d3e19ee0dd8960
  endif
else ifeq ($(ARCH),mips64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=b79090caee28ce266829ae82edb97ac18c65c6c570625912533d46753def0515
else ifeq ($(ARCH),mips64el)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64el-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=bafed35c8e081d8781651180bd3929542704e098ef5fbcf92a6aa7a75e5498b0
else ifeq ($(ARCH),i386)
  ifneq ($(CONFIG_TARGET_x86_geode)$(CONFIG_TARGET_x86_legacy),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@i686@fast+lto
    PKG_HASH:=1149d9fdcf0ca798c63624e62e6c76314aa7b0940e782cc0d064e618772c4b22
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@pentium4@fast+lto
    PKG_HASH:=51d491096c52f0e39a617817f3721f8d4be459a2f40afe0e19c6f1c3a35f5c26
  endif
else ifeq ($(ARCH),x86_64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@x86_64-linux-musl@x86_64@fast+lto
  PKG_HASH:=4b9548191b856690182f98b721512b9a50004986ecebf6eeed71cb709acbd1f5
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
  DEPENDS:=@(aarch64||arm||i386||mips||mipsel||mips64||mips64el||x86_64)
endef

define Build/Compile
endef

define Package/chinadns-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin/chinadns-ng
endef

$(eval $(call BuildPackage,chinadns-ng))
