#!/bin/bash
# --------------------------------------------------------
# Script to compile and create files for each openwrt
# --------------------------------------------------------
#1. Modify default IP
sed -i 's/192.168.1.1/192.168.3.1/g' openwrt/package/base-files/files/bin/config_generate

date=`date +%m.%d`
date1=`date +%h`
sed -i "s/DISTRIB_DESCRIPTION.*/DISTRIB_DESCRIPTION=\'Openwrt\'/g" package/base-files/files/etc/openwrt_release
sed -i "s/DISTRIB_REVISION.*/DISTRIB_REVISION=\'$date\'/g" package/base-files/files/etc/openwrt_release
sed -i "s/DISTRIB_RELEASE.*/DISTRIB_RELEASE=\'$date1\'/g" package/base-files/files/etc/openwrt_release

#2. 修改自定义固件名,增加编译日期(by:kenzo）
sed -i "s/IMG_PREFIX:=$(VERSION_DIST_SANITIZED)=\"IMG_PREFIX:=$(shell date +%m-%d)-$(VERSION_DIST_SANITIZED)'\"/g" include/image.mk

exit
