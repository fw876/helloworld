# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=2025.08.09
PKG_RELEASE:=1

ifeq ($(ARCH),aarch64)
  ifneq (,$(filter $(BOARD),rockchip qualcommax))
    PKG_ARCH:=$(PKG_NAME)+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=3fe0217615dd7060b7287d2b6b31d2a0b364137398bfb335a03bead322eac716
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
    PKG_HASH:=42ddd494200ec6d88b35902927688d316bc23e06e6c08d9e01eb2412196ab845
  endif
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v5t+soft_float@fast+lto
    PKG_HASH:=46ce65b0e2342d4f8dac63f281a38a239d8de29d6c75f863c797b164ab8e72cc
  else ifneq ($(filter $(ARM_CPU_FEATURES),vfp vfpv2),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabi@generic+v6+soft_float@fast+lto
    PKG_HASH:=0a401d1dc11129481b2baf86f847d55d66bd7e725cba4bf57875fdad27ef0052
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@arm-linux-musleabihf@generic+v7a@fast+lto
    PKG_HASH:=dfa1f6ba80fb0925613822f4c4e00df8da68e7b8b772048d26a0d1a9d07d346b
  endif
else ifeq ($(ARCH),mips)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips-linux-musl@mips32+soft_float@fast+lto
  PKG_HASH:=b610821a8f61b0ed3c8c7e82e10d401348a9de17f900988589024a37c4099c8e
else ifeq ($(ARCH),mipsel)
  ifeq ($(CONFIG_HAS_FPU),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32+soft_float@fast+lto
    PKG_HASH:=760544a88724e3b1b9eac79c9400231e81aa8786f8f00a979229e175811ffe6d
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@mipsel-linux-musl@mips32@fast+lto
    PKG_HASH:=ec547c31a884e0967437ceb90a5c270864efe81b0e40939e0ec2810c7bfd6653
  endif
else ifeq ($(ARCH),mips64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=2d0fce18a7ef1d74fdc12738767e66998a52c2b30d8790da760933853fe8726e
else ifeq ($(ARCH),mips64el)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@mips64el-linux-musl@mips64+soft_float@fast+lto
  PKG_HASH:=a301d8d200d06582c60bbe0e487a28f5b41e6f0997a548cf882a7b078dab089c
else ifeq ($(ARCH),i386)
  ifneq ($(CONFIG_TARGET_x86_geode)$(CONFIG_TARGET_x86_legacy),)
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@i686@fast+lto
    PKG_HASH:=85e057dd0a0e8913b30471737436ab8b71834c494ed9f9e53544261b1ffdc8d6
  else
    PKG_ARCH:=$(PKG_NAME)+wolfssl@i386-linux-musl@pentium4@fast+lto
    PKG_HASH:=2d0f1a05c82f2e21e71a6618c7f1d2e7f46aa6a21535d774d517e87ec00c989b
  endif
else ifeq ($(ARCH),x86_64)
  PKG_ARCH:=$(PKG_NAME)+wolfssl@x86_64-linux-musl@x86_64@fast+lto
  PKG_HASH:=842ea4e9816efd91d39bc76ead5c4a42e79011757e37c521b4270b675cfcb30c
else ifeq ($(ARCH),riscv64)
  PKG_ARCH:=chinadns-ng+wolfssl@riscv64-linux-musl@baseline_rv64@fast+lto
  PKG_HASH:=7056f47f4d6b20109e007792694dc83e5eac44c9265d7be20f6dc10375b35a9b
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
