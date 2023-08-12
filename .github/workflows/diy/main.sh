#!/bin/bash
function git_clone() {
  git clone --depth 1 $1 $2 || true
 }
function git_sparse_clone() {
  branch="$1" rurl="$2" localdir="$3" && shift 3
  git clone -b $branch --depth 1 --filter=blob:none --sparse $rurl $localdir
  cd $localdir
  git sparse-checkout init --cone
  git sparse-checkout set $@
  mv -n $@ ../
  cd ..
  rm -rf $localdir
  }
function mvdir() {
mv -n `find $1/* -maxdepth 0 -type d` ./
rm -rf $1
}

git clone --depth 1 -b luci https://github.com/xiaorouji/openwrt-passwall passwall-luci && mv -n passwall-luci/luci-app-passwall ./ ; rm -rf passwall-luci
git clone --depth 1 -b packages https://github.com/xiaorouji/openwrt-passwall passwall-packages && mv -n passwall-packages/* ./ && rm -rf passwall-packages
git clone --depth 1 -b dev https://github.com/vernesong/OpenClash && mv -n OpenClash/luci-app-openclash ./; rm -rf OpenClash
git clone --depth 1 -b master https://github.com/rufengsuixing/luci-app-adguardhome

git clone --depth=1 https://github.com/pymumu/openwrt-smartdns smartdns
git clone --depth=1 -b lede https://github.com/pymumu/luci-app-smartdns

git clone --depth 1 -b 18.06 https://github.com/jerrykuku/luci-theme-argon
git clone --depth 1 -b 18.06 https://github.com/jerrykuku/luci-app-argon-config
git clone --depth 1 https://github.com/gngpp/luci-theme-design
git clone --depth 1 https://github.com/gngpp/luci-app-design-config
git clone --depth 1 https://github.com/kenzok78/luci-theme-argone
git clone --depth 1 https://github.com/kenzok78/luci-app-argone-config
git clone --depth 1 -b 18.06 https://github.com/kiddin9/luci-theme-edge
git clone --depth 1 https://github.com/kenzok8/litte && mv -n litte/luci-theme-atmaterial_new litte/luci-theme-tomato ./ ; rm -rf litte

# git clone --depth 1 https://github.com/kiddin9/openwrt-adguardhome && mvdir openwrt-adguardhome
# git clone --depth 1 -b luci https://github.com/xiaorouji/openwrt-passwall passwall && mv -n passwall/luci-app-passwall ./;rm -rf passwall
# git clone --depth 1 https://github.com/vernesong/OpenClash && mv -n OpenClash/luci-app-openclash ./; rm -rf OpenClash
# git clone --depth 1 https://github.com/fw876/helloworld && mv -n helloworld/{luci-app-ssr-plus,tuic-client} ./ ; rm -rf helloworld
# git clone --depth 1 https://github.com/Hyy2001X/AutoBuild-Packages && rm -rf AutoBuild-Packages/luci-app-adguardhome && mvdir AutoBuild-Packages
# git clone --depth 1 https://github.com/immortalwrt/packages && mv -n packages/net/cdnspeedtest ./ ; rm -rf packages
# git clone --depth 1 -b openwrt-18.06 https://github.com/immortalwrt/luci && mv -n luci/applications/luci-app-gost luci/applications/luci-app-filebrowser ./ ; rm -rf luci
# git clone --depth 1 -b lede https://github.com/pymumu/luci-app-smartdns
# git clone --depth 1 https://github.com/coolsnowwolf/packages && mv -n packages/multimedia/UnblockNeteaseMusic-Go packages/net/msd_lite ./ ; rm -rf packages
# git clone --depth 1 https://github.com/jerrykuku/luci-app-jd-dailybonus
# git clone --depth 1 https://github.com/QiuSimons/openwrt-mos && mv -n openwrt-mos/luci-app-mosdns ./ ; rm -rf openwrt-mos
# git clone --depth 1 https://github.com/silime/luci-app-xunlei
# git clone --depth 1 https://github.com/sirpdboy/luci-app-netdata
# git clone --depth 1 https://github.com/kenzok8/wall && mv -n wall/* ./ ; rm -rf {alist,mosdns} && rm -rf wall

git clone --depth 1 https://github.com/xiaorouji/openwrt-passwall2 passwall2 && mv -n passwall2/luci-app-passwall2 ./;rm -rf passwall2
git clone --depth 1 https://github.com/fw876/helloworld && mv -n helloworld/{luci-app-ssr-plus,lua-neturl,redsocks2,v2raya} ./ ; rm -rf helloworld
git clone --depth 1 https://github.com/jerrykuku/luci-app-vssr
git clone --depth 1 https://github.com/yichya/luci-app-xray

git clone --depth 1 https://github.com/kiddin9/my-packages && mvdir my-packages
git clone --depth 1 https://github.com/Lienol/openwrt-package && mvdir openwrt-package
git clone --depth 1 https://github.com/linkease/openwrt-app-actions && mv -n openwrt-app-actions/applications/* ./;rm -rf openwrt-app-actions

git clone --depth 1 https://github.com/sirpdboy/luci-app-ddns-go ddnsgo && mv -n ddnsgo/* ./; rm -rf ddnsgo
git clone --depth 1 https://github.com/sirpdboy/sirpdboy-package && mv -n sirpdboy-package/luci-app-dockerman ./ ; rm -rf sirpdboy-package 
git clone --depth 1 https://github.com/peter-tank/luci-app-fullconenat

git clone --depth 1 https://github.com/kiddin9/openwrt-packages && mv -n openwrt-packages/luci-app-bypass openwrt-packages/luci-app-fileassistant ./ ; rm -rf openwrt-packages
git clone --depth 1 https://github.com/kiddin9/luci-app-dnsfilter
git clone --depth 1 https://github.com/kiddin9/luci-app-cloudreve
git clone --depth 1 https://github.com/kiddin9/aria2
git clone --depth 1 https://github.com/kiddin9/luci-app-baidupcs-web
git clone --depth 1 https://github.com/kiddin9/qBittorrent-Enhanced-Edition
git clone --depth 1 https://github.com/kiddin9/autoshare && mvdir autoshare
git clone --depth 1 https://github.com/kiddin9/openwrt-openvpn && mvdir openwrt-openvpn
git clone --depth 1 https://github.com/kiddin9/luci-app-xlnetacc
git clone --depth 1 https://github.com/kiddin9/luci-app-wizard

git clone --depth 1 https://github.com/ysc3839/openwrt-minieap
git clone --depth 1 https://github.com/ysc3839/luci-proto-minieap
git clone --depth 1 https://github.com/BoringCat/luci-app-mentohust
git clone --depth 1 https://github.com/BoringCat/luci-app-minieap
git clone --depth 1 https://github.com/peter-tank/luci-app-dnscrypt-proxy2
git clone --depth 1 https://github.com/peter-tank/luci-app-autorepeater
git clone --depth 1 https://github.com/rufengsuixing/luci-app-autoipsetadder
git clone --depth 1 https://github.com/ElvenP/luci-app-onliner
git clone --depth 1 https://github.com/rufengsuixing/luci-app-usb3disable
git clone --depth 1 https://github.com/riverscn/openwrt-iptvhelper && mvdir openwrt-iptvhelper
git clone --depth 1 https://github.com/KyleRicardo/MentoHUST-OpenWrt-ipk
git clone --depth 1 https://github.com/NateLol/luci-app-beardropper
git clone --depth 1 https://github.com/yaof2/luci-app-ikoolproxy
git clone --depth 1 https://github.com/project-lede/luci-app-godproxy
git clone --depth 1 https://github.com/tty228/luci-app-wechatpush
git clone --depth 1 https://github.com/4IceG/luci-app-sms-tool smstool && mvdir smstool

git clone --depth 1 https://github.com/BCYDTZ/luci-app-UUGameAcc
git clone --depth 1 https://github.com/ntlf9t/luci-app-easymesh
git clone --depth 1 https://github.com/zzsj0928/luci-app-pushbot
git clone --depth 1 https://github.com/shanglanxin/luci-app-homebridge
git clone --depth 1 https://github.com/esirplayground/luci-app-poweroff
git clone --depth 1 https://github.com/esirplayground/LingTiGameAcc
git clone --depth 1 https://github.com/esirplayground/luci-app-LingTiGameAcc
git clone --depth 1 https://github.com/brvphoenix/luci-app-wrtbwmon wrtbwmon1 && mvdir wrtbwmon1
git clone --depth 1 https://github.com/brvphoenix/wrtbwmon wrtbwmon2 && mvdir wrtbwmon2

git clone --depth 1 https://github.com/jerrykuku/luci-app-ttnode
git clone --depth 1 https://github.com/jerrykuku/luci-app-go-aliyundrive-webdav
git clone --depth 1 https://github.com/jerrykuku/lua-maxminddb
git clone --depth 1 https://github.com/sirpdboy/luci-app-advanced
git clone --depth 1 https://github.com/sirpdboy/luci-theme-opentopd
git clone --depth 1 https://github.com/sirpdboy/luci-app-poweroffdevice
git clone --depth 1 https://github.com/sirpdboy/luci-app-autotimeset
git clone --depth 1 https://github.com/sirpdboy/luci-app-lucky lucik && mv -n lucik/luci-app-lucky ./ ; rm -rf lucik
git clone --depth 1 https://github.com/sirpdboy/luci-app-partexp
git clone --depth 1 https://github.com/sirpdboy/chatgpt-web

git clone --depth 1 https://github.com/sirpdboy/netspeedtest speedtest && mv -f speedtest/*/ ./ && rm -rf speedtest

git clone --depth 1 https://github.com/KFERMercer/luci-app-tcpdump
git clone --depth 1 https://github.com/jefferymvp/luci-app-koolproxyR
git clone --depth 1 https://github.com/wolandmaster/luci-app-rtorrent
git clone --depth 1 https://github.com/NateLol/luci-app-oled
git clone --depth 1 https://github.com/hubbylei/luci-app-clash
git clone --depth 1 https://github.com/destan19/OpenAppFilter && mvdir OpenAppFilter
git clone --depth 1 https://github.com/lvqier/luci-app-dnsmasq-ipset
git clone --depth 1 https://github.com/walkingsky/luci-wifidog luci-app-wifidog
git clone --depth 1 https://github.com/CCnut/feed-netkeeper && mvdir feed-netkeeper
git clone --depth 1 https://github.com/sensec/luci-app-udp2raw
git clone --depth 1 https://github.com/LGA1150/openwrt-sysuh3c && mvdir openwrt-sysuh3c

git clone --depth 1 https://github.com/gdck/luci-app-cupsd cupsd1 && mv -n cupsd1/luci-app-cupsd cupsd1/cups/cups ./ ; rm -rf cupsd1

git clone --depth 1 https://github.com/sundaqiang/openwrt-packages && mv -n openwrt-packages/luci-* ./; rm -rf openwrt-packages
git clone --depth 1 https://github.com/zxlhhyccc/luci-app-v2raya
git clone --depth 1 https://github.com/kenzok8/luci-theme-ifit ifit && mv -n ifit/luci-theme-ifit ./;rm -rf ifit
git clone --depth 1 https://github.com/kenzok78/openwrt-minisign

git clone --depth 1 https://github.com/ophub/luci-app-amlogic amlogic && mv -n amlogic/luci-app-amlogic ./;rm -rf amlogic
git clone --depth 1 https://github.com/linkease/nas-packages && mv -n nas-packages/{network/services/*,multimedia/*} ./; rm -rf nas-packages
git clone --depth 1 https://github.com/linkease/nas-packages-luci && mv -n nas-packages-luci/luci/* ./; rm -rf nas-packages-luci
git clone --depth 1 https://github.com/linkease/istore && mv -n istore/luci/* ./; rm -rf istore
git clone --depth 1 https://github.com/AlexZhuo/luci-app-bandwidthd

git clone --depth 1 https://github.com/ZeaKyX/luci-app-speedtest-web
git clone --depth 1 https://github.com/ZeaKyX/speedtest-web
git clone --depth 1 https://github.com/Huangjoe123/luci-app-eqos
git clone --depth 1 https://github.com/honwen/luci-app-aliddns
git clone --depth 1 https://github.com/immortalwrt/homeproxy
git clone --depth 1 https://github.com/ximiTech/luci-app-msd_lite
git clone --depth 1 -b master https://github.com/UnblockNeteaseMusic/luci-app-unblockneteasemusic
git clone --depth 1 https://github.com/sbwml/luci-app-alist openwrt-alist && mv -n openwrt-alist/*alist ./ ; rm -rf openwrt-alist

git clone --depth 1 https://github.com/messense/aliyundrive-webdav aliyundrive && mv -n aliyundrive/openwrt/* ./ ; rm -rf aliyundrive
git clone --depth 1 https://github.com/messense/aliyundrive-fuse aliyundrive && mv -n aliyundrive/openwrt/* ./;rm -rf aliyundrive

git clone --depth 1 https://github.com/sbwml/luci-app-mosdns openwrt-mos && mv -n openwrt-mos/{*mosdns,v2dat} ./; rm -rf openwrt-mos

git clone --depth 1 https://github.com/SSSSSimon/tencentcloud-openwrt-plugin-ddns && mv -n tencentcloud-openwrt-plugin-ddns/tencentcloud_ddns ./luci-app-tencentddns; rm -rf tencentcloud-openwrt-plugin-ddns
git clone --depth 1 https://github.com/Tencent-Cloud-Plugins/tencentcloud-openwrt-plugin-cos && mv -n tencentcloud-openwrt-plugin-cos/tencentcloud_cos ./luci-app-tencentcloud-cos; rm -rf tencentcloud-openwrt-plugin-cos

git clone --depth 1 https://github.com/mingxiaoyu/luci-app-cloudflarespeedtest cloudflarespeedtest && mv -n cloudflarespeedtest/applications/* ./;rm -rf cloudflarespeedtest
git clone --depth 1 https://github.com/doushang/luci-app-shortcutmenu luci-shortcutmenu && mv -n luci-shortcutmenu/luci-app-shortcutmenu ./ ; rm -rf luci-shortcutmenu
git clone --depth 1 https://github.com/sbilly/netmaker-openwrt && mv -n netmaker-openwrt/netmaker ./; rm -rf netmaker-openwrt

svn export https://github.com/coolsnowwolf/luci/trunk/libs/luci-lib-ipkg
svn export https://github.com/x-wrt/packages/trunk/net/nft-qos
svn export https://github.com/x-wrt/luci/trunk/applications/luci-app-nft-qos
svn export https://github.com/Lienol/openwrt-package/branches/other/lean/luci-app-autoreboot
svn export https://github.com/openwrt/packages/trunk/net/shadowsocks-libev
# svn export https://github.com/kenzok8/jell/trunk/gn
svn export https://github.com/kenzok8/jell/trunk/luci-app-bridge

svn export https://github.com/Ysurac/openmptcprouter-feeds/trunk/luci-app-iperf
svn export https://github.com/QiuSimons/OpenWrt-Add/trunk/luci-app-irqbalance
svn export https://github.com/sirpdboy/sirpdboy-package/trunk/luci-app-control-speedlimit
svn export https://github.com/openwrt/luci/branches/openwrt-18.06/applications/luci-app-wireguard

git_sparse_clone master "https://github.com/coolsnowwolf/packages" "leanpack" net/miniupnpd net/mwan3 multimedia/UnblockNeteaseMusic-Go \
multimedia/UnblockNeteaseMusic net/amule net/antileech net/baidupcs-web net/frp multimedia/gmediarender net/go-aliyundrive-webdav \
net/qBittorrent-static net/phtunnel libs/qtbase libs/qttools libs/rblibtorrent net/msd_lite net/uugamebooster net/verysync net/vlmcsd \
net/dnsforwarder net/nps net/tcpping net/netatalk net/pgyvpn

git_sparse_clone openwrt-18.06 "https://github.com/immortalwrt/packages" "immpack" net/mwol net/sub-web net/dnsproxy net/haproxy net/v2raya \
net/cdnspeedtest net/keepalived net/microsocks net/go-nats net/go-wol net/simple-torrent net/bitsrunlogin-go net/transfer net/cloudreve \
net/subconverter net/ngrokc net/oscam net/njitclient net/scutclient net/gost net/gowebdav net/qBittorrent-Enhanced-Edition libs/jpcre2 \
libs/wxbase libs/rapidjson libs/libcron libs/quickjspp libs/toml11 libs/libtorrent-rasterbar libs/libdouble-conversion libs/qt6base \
libs/cxxopts libs/alac utils/qt6tools utils/cpulimit utils/filebrowser utils/cups utils/cups-bjnp utils/joker net/udp2raw multimedia/you-get \
multimedia/lux multimedia/ykdl multimedia/gallery-dl devel/go-rice admin/gotop

git_sparse_clone openwrt-18.06 "https://github.com/immortalwrt/immortalwrt" "immortal" package/kernel/rtl88x2bu package/kernel/r8168 \
package/kernel/rtl8821cu package/kernel/rtl8189es package/emortal/autocore package/emortal/automount package/network/utils/fullconenat \
package/network/utils/nftables package/libs/libnftnl package/firmware/wireless-regdb

git_sparse_clone develop "https://github.com/Ysurac/openmptcprouter-feeds" "enmptcp" luci-app-snmpd luci-app-packet-capture luci-app-mail msmtp

git_sparse_clone master "https://github.com/x-wrt/com.x-wrt" "x-wrt" natflow lua-ipops luci-app-macvlan

git_sparse_clone openwrt-18.06 "https://github.com/openwrt/openwrt" "openwrt" package/base-files package/network/config/firewall package/system/opkg \
package/network/services/ppp package/network/services/dnsmasq package/libs/openssl

git_sparse_clone openwrt-18.06 "https://github.com/openwrt/packages" "oppackages" utils/watchcat net/ddns-scripts net/nginx net/ariang \
admin/netdata net/rp-pppoe

git_sparse_clone openwrt-18.06 "https://github.com/openwrt/luci" "opluci" applications/luci-app-attendedsysupgrade applications/luci-app-aria2 \
applications/luci-app-ddns applications/luci-app-firewall applications/luci-app-watchcat applications/luci-app-upnp applications/luci-app-transmission \
modules/luci-base 

git_sparse_clone master "https://github.com/coolsnowwolf/luci" "leluci" applications libs/luci-lib-fs
mv -f applications luciapp
rm -rf luciapp/{luci-app-qbittorrent,luci-app-cpufreq}

git_sparse_clone openwrt-18.06 "https://github.com/immortalwrt/luci" "immluci" applications protocols/luci-proto-minieap
mv -n applications/* luciapp/; rm -rf applications

git_sparse_clone master "https://github.com/coolsnowwolf/lede" "leanlede" package/lean package/wwan package/network/services/shellsync

# Delete duplicated packages
mv -n luciapp/* ./ ; rm -Rf luciapp
mv -n lean/* ./ ; rm -Rf lean
mv -n wwan/*/* ./; rm -rf wwan
rm -Rf */.git


sed -i \
-e 's?include \.\./\.\./\(lang\|devel\)?include $(TOPDIR)/feeds/packages/\1?' \
-e 's?2. Clash For OpenWRT?3. Applications?' \
-e 's?\.\./\.\./luci.mk?$(TOPDIR)/feeds/luci/luci.mk?' \
-e 's/ca-certificates/ca-bundle/' \
-e 's/php7/php8/g' \
-e 's/+docker /+docker +dockerd /g' \
*/Makefile

sed -i 's/luci-lib-ipkg/luci-base/g' luci-app-store/Makefile
sed -i "/minisign:minisign/d" luci-app-dnscrypt-proxy2/Makefile
sed -i 's/+dockerd/+dockerd +cgroupfs-mount/' luci-app-docker*/Makefile
sed -i '$i /etc/init.d/dockerd restart &' luci-app-docker*/root/etc/uci-defaults/*
sed -i 's/+libcap /+libcap +libcap-bin /' luci-app-openclash/Makefile
sed -i 's/\(+luci-compat\)/\1 +luci-theme-argon/' luci-app-argon-config/Makefile
sed -i 's/\(+luci-compat\)/\1 +luci-theme-design/' luci-app-design-config/Makefile
sed -i 's/\(+luci-compat\)/\1 +luci-theme-argone/' luci-app-argone-config/Makefile
sed -i 's/ +uhttpd-mod-ubus//' luci-app-packet-capture/Makefile
sed -i 's/	ip.neighbors/	luci.ip.neighbors/' luci-app-wifidog/luasrc/model/cbi/wifidog/wifidog_cfg.lua
#sed -i -e 's/nas/services/g' -e 's/NAS/Services/g' $(grep -rl 'nas\|NAS' luci-app-fileassistant)
#sed -i -e 's/nas/services/g' -e 's/NAS/Services/g' $(grep -rl 'nas\|NAS' luci-app-alist)
#sed -i '65,73d' adguardhome/Makefile
#sed -i 's/PKG_SOURCE_DATE:=2/PKG_SOURCE_DATE:=3/' transmission-web-control/Makefile

exit 0

