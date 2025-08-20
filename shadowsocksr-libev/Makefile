# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2018 Lean <coolsnowwolf@gmail.com>
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocksr-libev
PKG_VERSION:=2.5.6
PKG_RELEASE:=12

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE

PKG_FIXUP:=autoreconf
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/shadowsocksr-libev/Default
  define Package/shadowsocksr-libev-ssr-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=shadowsocksr-libev ssr-$(1)
    URL:=https://github.com/shadowsocksrr/shadowsocksr-libev
    DEPENDS:=+libev +libsodium +libopenssl +libpthread +libpcre2 +libudns +zlib
  endef

  define Package/shadowsocksr-libev-ssr-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/usr/bin/ss-$(1) $$(1)/usr/bin/ssr-$(1)
  endef
endef

SHADOWSOCKSR_COMPONENTS:=check local nat redir server
define shadowsocksr-libev/templates
  $(foreach component,$(SHADOWSOCKSR_COMPONENTS),
    $(call Package/shadowsocksr-libev/Default,$(component))
  )
endef
$(eval $(call shadowsocksr-libev/templates))

CONFIGURE_ARGS += \
	--disable-documentation \
	--disable-ssp \
	--disable-assert \
	--enable-system-shared-lib

TARGET_CFLAGS += -flto
TARGET_LDFLAGS += -Wl,--gc-sections,--as-needed

$(foreach component,$(SHADOWSOCKSR_COMPONENTS), \
  $(eval $(call BuildPackage,shadowsocksr-libev-ssr-$(component))) \
)
