# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=shadow-tls
PKG_VERSION:=0.2.23
PKG_RELEASE:=1

PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=FluffyTigerFear
RELEASE_HEAD:=$(PKG_NAME)
RELEASE_FOOT:=unknown-linux-musl
ifeq ($(ARCH),aarch64)
	RELEASE_ARCH:=$(RELEASE_HEAD)-aarch64-$(RELEASE_FOOT)
	PKG_HASH:=62081cdb011bcf82064c0f3313ee581df536914106108b137efdc5014c207b5b
else ifeq ($(ARCH),arm)
	ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
	ifeq ($(ARM_CPU_FEATURES),)
		RELEASE_ARCH:=$(RELEASE_HEAD)-armv7-$(RELEASE_FOOT)eabi
		PKG_HASH:=eb1346ec83e154f2722ab671fbcdd1c95739b4a7c29655effae9cd4ffe8d23b6
	else
		RELEASE_ARCH:=$(RELEASE_HEAD)-armv7-$(RELEASE_FOOT)eabihf
		PKG_HASH:=be005c23a4d5c51d52f2a96f1f060734dd43b80a7912516c130d433d04c7dfa1
	endif
else ifeq ($(ARCH),x86_64)
	RELEASE_ARCH:=$(RELEASE_HEAD)-x86_64-$(RELEASE_FOOT)
	PKG_HASH:=acc7296e50cf310a15fca5756efa5f721ffc62dd0e4dd16581bc229b21b4b549
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
