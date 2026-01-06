# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 ImmortalWrt.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tuic-client
PKG_VERSION:=1.6.7
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/Itsusinn/tuic/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=72991ce379638445c7f840993f7fafa0f391c7d4169ec51fe25a45cb7754c577
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

TAR_OPTIONS += --strip-components 1
TAR_CMD=$(HOST_TAR) -C $(1) $(TAR_OPTIONS)

define Package/tuic-client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=TUIC proxy protocol client
  URL:=https://github.com/EAimTY/tuic
  DEPENDS:=@(aarch64||arm||mips||mipsel||x86_64||i386||i686||riscv64||loongarch64)
endef

define Package/tuic-client/description
  Delicately-TUICed 0-RTT proxy protocol client.
endef

define Select/Features
$(strip \
  $(if $(findstring x86_64,$(RUSTC_TARGET_ARCH)),--features jemallocator) \
  $(if $(findstring aarch64,$(RUSTC_TARGET_ARCH)),--features jemallocator) \
  $(if $(or \
    $(findstring arm,$(RUSTC_TARGET_ARCH)), \
    $(findstring mips,$(RUSTC_TARGET_ARCH)), \
    $(findstring mipsel,$(RUSTC_TARGET_ARCH)), \
    $(findstring i686,$(RUSTC_TARGET_ARCH)), \
    $(findstring i386,$(RUSTC_TARGET_ARCH)), \
    $(findstring riscv64,$(RUSTC_TARGET_ARCH)), \
    $(findstring loongarch64,$(RUSTC_TARGET_ARCH)) \
  ),--no-default-features --features ring) \
)
endef

define Build/Compile
	( \
		pushd $(PKG_BUILD_DIR) ; \
		$(CARGO_PKG_CONFIG_VARS) \
		cargo build --release \
			-p tuic-client \
			--target $(RUSTC_TARGET_ARCH) \
			$(call Select/Features) ; \
		popd ; \
	)
endef

define Package/tuic-client/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/tuic-client $(1)/usr/bin/
endef

$(eval $(call RustBinPackage,tuic-client))
$(eval $(call BuildPackage,tuic-client))
