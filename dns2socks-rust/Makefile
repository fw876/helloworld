# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2024 Zxlhhyccc <zxlhhyccc@gmail.com>
# Copyright (C) 2021-2024 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=dns2socks-rust
PKG_VERSION:=0.2.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/tun2proxy/dns2socks.git
PKG_SOURCE_DATE:=2025-08-18
PKG_SOURCE_VERSION:=a23fe67ff4e2a218fcd4726055514c8c2b5299c9
PKG_MIRROR_HASH:=7d2829cc0da6e9eacc5ed97f51f37ee0ce1ea1a10f38f1e4d2a30ae80d237289

PKG_MAINTAINER:=Zxlhhyccc <zxlhhyccc@gmail.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

#RUST_PKG:=dns2socks

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/dns2socks-rust
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=IP Addresses and Names
    TITLE:=DNS forwards to SOCKS5 server
    URL:=https://github.com/tun2proxy/dns2socks.git
    DEPENDS:=$$(RUST_ARCH_DEPENDS)
endef

define Package/dns2socks-rust/description
  This is a DNS server that forwards DNS requests to a SOCKS5 server.
endef

define Build/Compile
	$(call Build/Compile/Cargo,,--all-features)
endef

define Package/dns2socks-rust/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/dns2socks $(1)/usr/bin/dns2socks-rust
endef

$(eval $(call BuildPackage,dns2socks-rust))
