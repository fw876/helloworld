include $(TOPDIR)/rules.mk

PKG_NAME:=xray-core
PKG_VERSION:=26.9.30
PKG_RELEASE:=6

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/XTLS/Xray-core/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=85162fa61eb6d1adc9199afff7b41299e69dedd094907e9c56ef665c236b3ef0

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MPL-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DIR:=$(BUILD_DIR)/Xray-core-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16
PKG_CONFIG_DEPENDS:=CONFIG_XRAY_CORE_NSS_TLS CONFIG_XRAY_CORE_NSS_DMABUF_TLS

GO_PKG:=github.com/xtls/xray-core
GO_PKG_LDFLAGS:=-s -w
GO_PKG_BUILD_PKG:=$(GO_PKG)/main
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/core.build=OpenWrt \
	$(GO_PKG)/core.version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/xray-core
  TITLE:=A platform for building proxies to bypass network restrictions
  SECTION:=net
  CATEGORY:=Network
  URL:=https://xtls.github.io
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
  EXTRA_DEPENDS:=$(if $(CONFIG_XRAY_CORE_NSS_TLS),kmod-cryptodev$(comma) kmod-qca-nss-cfi-cryptoapi$(if $(CONFIG_XRAY_CORE_NSS_DMABUF_TLS),$(comma) kmod-nss-crypto-dmabuf))
endef

define Package/xray-core/config
  config XRAY_CORE_NSS_TLS
    bool "Build optional NSS TLS AES-GCM backend"
    depends on PACKAGE_xray-core && (TARGET_ipq60xx || TARGET_ipq807x)
    select PACKAGE_kmod-cryptodev if PACKAGE_xray-core
    select PACKAGE_kmod-qca-nss-cfi-cryptoapi if PACKAGE_xray-core
    default y
    help
      Build cryptodev support for TLS 1.2/1.3 and uTLS AES-GCM.
      Enable at runtime with XRAY_NSS_TLS=cryptodev. CPU is the default.

  config XRAY_CORE_NSS_DMABUF_TLS
    bool "Include NSS DMA-BUF/CMA record driver"
    depends on XRAY_CORE_NSS_TLS
    select PACKAGE_kmod-nss-crypto-dmabuf if PACKAGE_xray-core
    default y
    help
      Include the dedicated registered-buffer driver and CMA kernel support.
      Requires rebuilding the kernel and all modules. Select at runtime with
      XRAY_NSS_TLS=dmabuf. This path requires hardware validation.
endef

ifeq ($(CONFIG_XRAY_CORE_NSS_TLS),y)
define Build/Compile
	$(GO_PKG_BUILD_VARS) python3 $(PKG_BUILD_DIR)/_nss/overlay.py $(PKG_BUILD_DIR) $(PKG_BUILD_DIR)/nss-overlay
	$(call GoPackage/Build/Compile,-overlay=$(PKG_BUILD_DIR)/nss-overlay/overlay.json -modfile=$(PKG_BUILD_DIR)/nss-overlay/go.mod)
endef
endif

define Package/xray-core/description
  Xray, Penetrates Everything. It helps you to build your own computer network.
  It secures your network connections and thus protects your privacy.
endef

define Package/xray-core/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/main $(1)/usr/bin/xray
endef

$(eval $(call BuildPackage,xray-core))
