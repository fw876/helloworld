# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2022 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=gn
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://gn.googlesource.com/gn.git
PKG_SOURCE_DATE:=2024-09-25
PKG_SOURCE_VERSION:=95b0f8fe31a992a33c040bbe3867901335c12762
PKG_MIRROR_HASH:=ccd429ad9055302126939603700193be12faecfc886f828d35a93b9a923dea3a

PKG_LICENSE:=BSD 3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_HOST_ONLY:=1
HOST_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk

define Package/gn
  SECTION:=devel
  CATEGORY:=Development
  TITLE:=A meta-build system that generates build files for Ninja
  URL:=https://gn.googlesource.com/gn/
  BUILDONLY:=1
endef

define Package/gn/description
  GN can generate Ninja build files for C, C++, Rust, Objective C,
  and Swift source on most popular platforms.
endef

define Host/Configure
	$(PYTHON) $(HOST_BUILD_DIR)/build/gen.py \
		--no-last-commit-position
endef

define Host/Compile
	+$(NINJA) -C $(HOST_BUILD_DIR)/out
endef

define Host/Install
	$(INSTALL_DIR) $(STAGING_DIR_HOSTPKG)/bin/
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/out/gn $(STAGING_DIR_HOSTPKG)/bin/
endef

define Host/Clean
	$(RM) $(STAGING_DIR_HOSTPKG)/bin/gn
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,gn))
