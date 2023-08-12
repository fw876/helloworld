#
# Copyright (C) 2006-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=miniupnpd-iptables
PKG_VERSION:=3022-08-31
PKG_RELEASE:=25

# Content-Encoding conflict, can refer to this [issue](https://github.com/miniupnp/miniupnp/issues/605)
# so switch mirror repo to http://miniupnp.tuxfamily.org
# PKG_SOURCE_URL:=http://miniupnp.free.fr/files
PKG_SOURCE_URL:=http://miniupnp.tuxfamily.org/files
PKG_SOURCE:=miniupnpd-2.0.20180503.tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/miniupnpd-2.0.20180503
PKG_HASH:=skip

PKG_MAINTAINER:=Markus Stenberg <fingon@iki.fi>
PKG_LICENSE:=BSD-3-Clause

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+iptables +libip4tc +libuuid
  PROVIDES:=miniupnpd
  TITLE:=Lightweight UPnP IGD, NAT-PMP & PCP daemon
  SUBMENU:=Firewall
  URL:=http://miniupnp.free.fr/
  VARIANT:=iptables
endef

define Package/$(PKG_NAME)/config
config MINIUPNPD_IGDv2
	bool
	default n
	prompt "Enable IGDv2"
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/upnpd
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh

if [ -z "$$IPKG_INSTROOT" ]; then
  ( . /etc/uci-defaults/99-miniupnpd )
  rm -f /etc/uci-defaults/99-miniupnpd
fi

exit 0
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	echo "OpenWrt" | tr \(\)\  _ >$(PKG_BUILD_DIR)/os.openwrt
endef

MAKE_FLAGS += \
	TARGET_OPENWRT=1 TEST=0 \
	LIBS="" \
	CC="$(TARGET_CC) -DIPTABLES_143 \
		-lip4tc -luuid" \
	CONFIG_OPTIONS="--portinuse --leasefile \
		$(if $(CONFIG_MINIUPNPD_IGDv2),--igd2)" \
	-f Makefile.linux \
	miniupnpd


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/etc/uci-defaults $(1)/etc/hotplug.d/iface $(1)/usr/share/miniupnpd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/miniupnpd $(1)/usr/sbin/miniupnpd
	$(INSTALL_BIN) ./files/miniupnpd.init $(1)/etc/init.d/miniupnpd
	$(INSTALL_CONF) ./files/upnpd.config $(1)/etc/config/upnpd
	$(INSTALL_DATA) ./files/miniupnpd.hotplug $(1)/etc/hotplug.d/iface/50-miniupnpd
	$(INSTALL_DATA) ./files/miniupnpd.defaults $(1)/etc/uci-defaults/99-miniupnpd
	$(INSTALL_DATA) ./files/firewall.include $(1)/usr/share/miniupnpd/firewall.include
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
