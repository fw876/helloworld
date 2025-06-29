# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=2025.06.20
PKG_RELEASE:=1

ifeq ($(ARCH),aarch64)
  ifneq (,$(filter $(BOARD),rockchip qualcommax))
    PKG_ARCH:=$(PKG_NAME)+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=224494b4505ac8dd347a70b298b853b677c0e247887d6edcf46b08bb153de017
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=7639fae8e77ea36e377352179acb19e2fdf9010c2c373a9e02f03f637e99140c
  endif
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v5t+soft_float@fast+lto
    PKG_HASH:=41af270fb2509aa011a75edaee57be5d9ebb543ec77615c6e7030ddeab8bbb9b
  else ifneq ($(filter $(ARM_CPU_FEATURES),vfp vfpv2),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v6+soft_float@fast+lto
    PKG_HASH:=00fe09cf6309377a4bc90f3a5b909c5266c63181cc268912b4e32f92f58ec6cd
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabihf@generic+v7a@fast+lto
    PKG_HASH:=1acd9129d7efd99bf9952ac6dd932e10108fb27a2a059f03e80bf520300b3741
  endif
else ifeq ($(ARCH),mips)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips-linux-musl@mips32+soft_float@fast+lto
  PKG_HASH:=fa468c04e58b47d7f6bb893ed6bdc41f9929d5a2e500c768e82e0f4a459b047c
else ifeq ($(ARCH),mipsel)
  ifeq ($(CONFIG_HAS_FPU),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32+soft_float@fast+lto
    PKG_HASH:=294917a5009a315cf5ad04cdda8f66714c60c928e2186a6846323e04aa4a798f
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32@fast+lto
    PKG_HASH:=23c40248c3aa301a26c37cdb66e2141d2d73d4f0c5c03c066324263510d959ac
  endif
else ifeq ($(ARCH),mips64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=f65bf9e495384afaf8aadd35395a2b9cdb2eedecb2602a0c522039dc4707350d
else ifeq ($(ARCH),mips64el)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64el-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=44bd1a96d5a0ce02b8c5c5d941339958af2bf2d1c5e5d90ed87214ac0d900543
else ifeq ($(ARCH),i386)
  ifneq ($(CONFIG_TARGET_x86_geode)$(CONFIG_TARGET_x86_legacy),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@i686@fast+lto
    PKG_HASH:=25a215e1b5c18f8b4f0e7f0a0925fd1c959bbfdfeb3383830d2b645a94077fc6
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@pentium4@fast+lto
    PKG_HASH:=e78feedf8fafc60749dfca576acd05b3df8e4b99912aa77a320971011ca77b1d
  endif
else ifeq ($(ARCH),x86_64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@x86_64-linux-musl@x86_64@fast+lto
  PKG_HASH:=9ad100ef18f7acaecad1aaa07b07029e9e50679fc8f119977878211b1ceb96f0
else ifeq ($(ARCH),riscv64)
  PKG_ARCH:=chinadns-ng+wolfssl@riscv64-linux-musl@baseline_rv64@fast+lto
  PKG_HASH:=ed4d2cf72c2d48f19dd7678f419ce726bc2a793afc62afd6345e735dd262ca96
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
  DEPENDS:=@(aarch64||arm||i386||mips||mipsel||mips64||mips64el||riscv64||x86_64)
endef

define Package/chinadns-ng/description
ChinaDNS Next Generation, refactoring with epoll and ipset.
endef

define Build/Compile
endef

define Package/chinadns-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/chinadns-ng $(1)/usr/bin
endef

$(eval $(call BuildPackage,chinadns-ng))
