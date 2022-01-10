# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-rust
PKG_VERSION:=1.12.5
PKG_RELEASE:=1

PKG_SOURCE_HEADER:=shadowsocks-v$(PKG_VERSION)
PKG_SOURCE_BODY:=unknown-linux-musl
PKG_SOURCE_BODY_GLIBC:=unknown-linux-gnu
PKG_SOURCE_FOOTER:=tar.xz
PKG_SOURCE_URL:=https://github.com/shadowsocks/shadowsocks-rust/releases/download/v$(PKG_VERSION)/

ifeq ($(ARCH),aarch64)
  ifneq ($(CONFIG_USE_GLIBC),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).aarch64-$(PKG_SOURCE_BODY_GLIBC).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=78c9e6638a6e186999d7ca3d1b119b29b7acc3922d733afe6f9b6454a97d9c7d
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).aarch64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=e891842b714f3f23fe8cb5d3187ac702f42bf8e6847fed65d174105fafad4d49
  endif
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    ifneq ($(CONFIG_USE_GLIBC),)
      PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY_GLIBC)eabi.$(PKG_SOURCE_FOOTER)
      PKG_HASH:=ec0a34b552eeb6fa983f85bd0f52ae8edee1d7155a8b0129875f1f5597b7f1a7
    else
      PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabi.$(PKG_SOURCE_FOOTER)
      PKG_HASH:=1a26ce3c55b3fdfc1041b20cb51b909c294e77dea23d7b4a0362c2d0310a7e08
    endif
  else
    ifneq ($(CONFIG_USE_GLIBC),)
      PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY_GLIBC)eabihf.$(PKG_SOURCE_FOOTER)
      PKG_HASH:=3b6b8cafe057c75256f3e34ea49b6c526101121d9f4b6caf6c0bd94fe02d9610
    else
      PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabihf.$(PKG_SOURCE_FOOTER)
      PKG_HASH:=6f664ee11bd5789fd1a2607e7ba5fbbbefd60079767928eef732fdbc137b401f
    endif
  endif
else ifeq ($(ARCH),i386)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).i686-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=721d23860d26a8047ca2978ed24de35219e0439e77e6722e0f87a54e9b7e1843
else ifeq ($(ARCH),mips)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mips-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=2bf294ea58d0bca8ee1f47b63632db341cdb3d849d67a0438695b7c7b589c7eb
else ifeq ($(ARCH),mipsel)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mipsel-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=19d62fbf7586939b402a65c86432410fe7612726f9840f7ee383e8a2cb6d7802
else ifeq ($(ARCH),x86_64)
  ifneq ($(CONFIG_USE_GLIBC),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).x86_64-$(PKG_SOURCE_BODY_GLIBC).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=7f034c232ebea9d0a31e7c5456b004ded1f13f0aa4927d90cd154f92af8061c8
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).x86_64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=0e8f7333e6a9baf8096bb05c41bbc7d447b5a4ba9a6eb1814a48116b18694cc3
  endif
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

define Package/shadowsocks-rust/Default
  define Package/shadowsocks-rust-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=shadowsocks-rust $(1)
    URL:=https://github.com/shadowsocks/shadowsocks-rust
    DEPENDS:=@(USE_MUSL||(USE_GLIBC&&aarch64)||(USE_GLIBC&&arm)||(USE_GLIBC&&x86_64)) @(aarch64||arm||i386||mips||mipsel||x86_64) @!(TARGET_x86_geode||TARGET_x86_legacy)
  endef

  define Package/shadowsocks-rust-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_BUILD_DIR)/$(1) $$(1)/usr/bin
  endef
endef

SHADOWSOCKS_COMPONENTS:=sslocal ssmanager ssserver ssurl ssservice
define shadowsocks-rust/templates
  $(foreach component,$(SHADOWSOCKS_COMPONENTS),
    $(call Package/shadowsocks-rust/Default,$(component))
  )
endef
$(eval $(call shadowsocks-rust/templates))

define Build/Compile
endef

$(foreach component,$(SHADOWSOCKS_COMPONENTS), \
  $(eval $(call BuildPackage,shadowsocks-rust-$(component))) \
)