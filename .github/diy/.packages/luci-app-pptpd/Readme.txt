添加如下代码到/feeds/luci.index


Source-Makefile: feeds/luci/applications/luci-app-pptpd/Makefile
Package: luci-app-pptpd
Submenu: 3. Applications
Version: x-1
Depends: +libc +SSP_SUPPORT:libssp +USE_GLIBC:librt +USE_GLIBC:libpthread +pptpd +kmod-mppe +ipset
Conflicts: 
Menu-Depends: 
Provides: 
Build-Depends: lua/host luci-base/host 
Section: luci
Category: LuCI
Title: LuCI page for PPTP VPN Server
Maintainer: 
Source: 
Type: ipkg
Description: LuCI page for PPTP VPN Server

@@
