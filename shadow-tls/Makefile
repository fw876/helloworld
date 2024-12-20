# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=shadow-tls
PKG_VERSION:=0.2.25
PKG_RELEASE:=1

PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=FluffyTigerFear
RELEASE_HEAD:=$(PKG_NAME)
RELEASE_FOOT:=unknown-linux-musl
ifeq ($(ARCH),aarch64)
	RELEASE_ARCH:=$(RELEASE_HEAD)-aarch64-$(RELEASE_FOOT)
	PKG_HASH:=3295476b37f549a68906519d3eaecb74bf3b6eaf9094cebb16ee84f0151373c6
else ifeq ($(ARCH),arm)
    ifeq ($(CONFIG_CPU_TYPE),cortex-a7)
        RELEASE_ARCH:=$(RELEASE_HEAD)-armv7-$(RELEASE_FOOT)eabihf
        PKG_HASH:=e6f918a072557c50fd0ea950af9a156a9b102af72c1d010ff85d08d13006c54f
    else ifeq ($(CONFIG_CPU_TYPE),cortex-a9)
        RELEASE_ARCH:=$(RELEASE_HEAD)-armv7-$(RELEASE_FOOT)eabihf
        PKG_HASH:=e6f918a072557c50fd0ea950af9a156a9b102af72c1d010ff85d08d13006c54f
    else
        RELEASE_ARCH:=$(RELEASE_HEAD)-arm-$(RELEASE_FOOT)eabi
        PKG_HASH:=b6743bc60e1727972ece0fd5acf3a931e5be05cedee6f637e7e3d8c5b8d58f16
    endif
else ifeq ($(ARCH),x86_64)
	RELEASE_ARCH:=$(RELEASE_HEAD)-x86_64-$(RELEASE_FOOT)
	PKG_HASH:=a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532
else
	PKG_SOURCE:=dummy
	PKG_HASH:=dummy
endif

define Download/shadow-tls
	URL:=https://github.com/ihciah/shadow-tls/releases/download/v$(PKG_VERSION)
	URL_FILE:=$(RELEASE_ARCH)
	FILE:=$(RELEASE_ARCH)
	HASH:=$(PKG_HASH)
endef

define Package/shadow-tls
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Web Servers/Proxies
	TITLE:=A proxy to expose real tls handshake to the firewall.
	URL:=https://github.com/ihciah/shadow-tls
	DEPENDS:=@USE_MUSL @(aarch64||arm||x86_64) @!(TARGET_x86_geode||TARGET_x86_legacy)
endef

define Build/Prepare
	$(call Build/Prepare/Default)
ifneq ($(CONFIG_PACKAGE_shadow-tls),)
	$(call Download,shadow-tls)
endif
endef

define Build/Compile
endef

define Package/shadow-tls/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(DL_DIR)/$(RELEASE_ARCH) $(1)/usr/bin/shadow-tls
endef

$(eval $(call BuildPackage,shadow-tls))
