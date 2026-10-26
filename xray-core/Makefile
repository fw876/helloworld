include $(TOPDIR)/rules.mk

PKG_NAME:=xray-core
PKG_VERSION:=26.10.21
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/XTLS/Xray-core/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=44ef4874529a03848c90f1fdcfb763350fbc5f1de741ec90e0024d651df25650

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MPL-2.0 GPL-3.0-or-later MIT
PKG_LICENSE_FILES:=LICENSE proxy/anytls/LICENSE.sing-anytls proxy/naive/LICENSE.sing-box proxy/shadowsocksr/LICENSE proxy/tuic/LICENSE.mihomo proxy/snell/LICENSE.mihomo transport/internet/shadowtls/LICENSE.mihomo transport/internet/kcptun/LICENSE.mihomo transport/internet/kcptun/LICENSE.kcptun

PKG_BUILD_DIR:=$(BUILD_DIR)/Xray-core-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=golang/host upx/host
PKG_CONFIG_DEPENDS:=CONFIG_XRAY_CORE_NAIVE
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/xtls/xray-core
GO_PKG_LDFLAGS:=-s -w
GO_PKG_BUILD_PKG:=$(GO_PKG)/main
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/core.build=OpenWrt \
	$(GO_PKG)/core.version=$(PKG_VERSION)

UPX_BIN:=$(firstword $(wildcard $(STAGING_DIR_HOSTPKG)/bin/upx $(STAGING_DIR_HOST)/bin/upx))

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# Cronet's native archives contain LLVM bitcode. Use its matching linker while
# retaining OpenWrt's target GCC, sysroot, ABI flags and C runtime.
CRONET_CLANG_VERSION:=llvmorg-24-init-3796-g20e97c4b-27
CRONET_CLANG_FILE:=clang-$(CRONET_CLANG_VERSION).tar.xz
CRONET_CLANG_DIR:=$(PKG_BUILD_DIR)/.cronet-clang

ifeq ($(CONFIG_XRAY_CORE_NAIVE),y)
  GO_PKG_TAGS+=with_naive_outbound
  ifeq ($(CONFIG_USE_MUSL),y)
    GO_PKG_TAGS+=with_musl
  endif
  # golang-package.mk also appends TARGET_LDFLAGS through -extldflags, after
  # CGO_LDFLAGS. Select LLD here so the SDK cannot override it with ld.bfd.
  TARGET_LDFLAGS:=$(filter-out -fuse-ld=%,$(TARGET_LDFLAGS)) -B$(CRONET_CLANG_DIR)/bin -fuse-ld=lld $(if $(filter arm i386 mipsel loongarch64,$(ARCH)),-Wl$(comma)-no-pie) $(if $(filter loongarch64,$(ARCH)),-Wl$(comma)--no-relax)

  define Download/cronet-clang
    URL:=https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64
    URL_FILE:=$(CRONET_CLANG_FILE)
    FILE:=$(CRONET_CLANG_FILE)
    HASH:=968195fa0b49958e066695df2c7c985d169a20fa06eedb8fcef900a6030edcb0
  endef
  $(eval $(call Download,cronet-clang))

  define Build/Prepare
	$(call Build/Prepare/Default)
	$(INSTALL_DIR) $(CRONET_CLANG_DIR)
	$(TAR) -xJf $(DL_DIR)/$(CRONET_CLANG_FILE) -C $(CRONET_CLANG_DIR)
  endef
endif

# Apply only to this package; runtime DT detection restricts use to AN7581.
# Resolve Go through the same versioned PATH and environment as the build.
ifeq ($(GO_ARCH),arm64)
  define Build/Compile
	$(GO_PKG_VARS) python3 $(PKG_BUILD_DIR)/tools/eip93/overlay.py --go go --out $(PKG_BUILD_DIR)/.eip93-overlay
	$(call GoPackage/Build/Compile,-overlay=$(PKG_BUILD_DIR)/.eip93-overlay/overlay.json)
  endef
endif

# Compress once per build, not once per package/rootfs installation.
# Keep Go's output intact and let the .built stamp guard the packed copy.
define Build/Install
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/.upx
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/main $(PKG_BUILD_DIR)/.upx/xray
	${UPX_BIN} --lzma --best $(PKG_BUILD_DIR)/.upx/xray
endef

# Go's -s -w flags strip the binary before UPX; do not strip it again.
RSTRIP:=:

define Package/xray-core
  TITLE:=A platform for building proxies to bypass network restrictions
  SECTION:=net
  CATEGORY:=Network
  URL:=https://xtls.github.io
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/xray-core/config
  config XRAY_CORE_NAIVE
    bool "Enable NaiveProxy outbound (Chromium/Cronet)"
    depends on PACKAGE_xray-core
    depends on (aarch64 || arm || i386 || x86_64 || mipsel || riscv64 || loongarch64)
    depends on (USE_MUSL || USE_GLIBC)
    depends on !arm || (arm_v7 && HAS_FPU)
    default y
    help
      Link Chromium/Cronet for NaiveProxy HTTP/2 and HTTP/3 outbounds.
      Requires an x86_64 Linux build host and adds a native library to Xray.
      Naive inbound support remains available when this option is disabled.
endef

define Package/xray-core/description
  Xray, Penetrates Everything. It helps you to build your own computer network.
  It secures your network connections and thus protects your privacy.
endef

define Package/xray-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/.upx/xray $(1)/usr/bin/xray
endef

$(eval $(call BuildPackage,xray-core))
