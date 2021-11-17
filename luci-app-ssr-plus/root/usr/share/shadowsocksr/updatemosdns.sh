#!/bin/bash

WORKDIR="/etc/mosdns"
TEMPDIR="/tmp/MosDNSupdatelist"

DOWNLOAD_LINK_GEOIP="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip-only-cn-private.dat"
DOWNLOAD_LINK_GEOSITE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

download_geoip() {
	if ! curl -s -L -H 'Cache-Control: no-cache' -o "${TEMPDIR}/geoip.dat.new" "$DOWNLOAD_LINK_GEOIP"; then
		echo 'error: Download failed! Please check your network or try again.'
		EXIT 4
	fi
	if ! curl -s -L -H 'Cache-Control: no-cache' -o "${TEMPDIR}/geoip.dat.sha256sum.new" "$DOWNLOAD_LINK_GEOIP.sha256sum"; then
		echo 'error: Download failed! Please check your network or try again.'
		EXIT 5
	fi
	SUM="$(sha256sum ${TEMPDIR}/geoip.dat.new | sed 's/ .*//')"
	CHECKSUM="$(sed 's/ .*//' ${TEMPDIR}/geoip.dat.sha256sum.new)"
	if [[ "$SUM" != "$CHECKSUM" ]]; then
		echo 'error: Check failed! Please check your network or try again.'
		EXIT 6
	fi
}

download_geosite() {
	if ! curl -s -L -H 'Cache-Control: no-cache' -o "${TEMPDIR}/geosite.dat.new" "$DOWNLOAD_LINK_GEOSITE"; then
		echo 'error: Download failed! Please check your network or try again.'
		EXIT 7
	fi
	if ! curl -s -L -H 'Cache-Control: no-cache' -o "${TEMPDIR}/geosite.dat.sha256sum.new" "$DOWNLOAD_LINK_GEOSITE.sha256sum"; then
		echo 'error: Download failed! Please check your network or try again.'
		EXIT 8
	fi
	SUM="$(sha256sum ${TEMPDIR}/geosite.dat.new | sed 's/ .*//')"
	CHECKSUM="$(sed 's/ .*//' ${TEMPDIR}/geosite.dat.sha256sum.new)"
	if [[ "$SUM" != "$CHECKSUM" ]]; then
		echo 'error: Check failed! Please check your network or try again.'
		EXIT 9
	fi
}

rename_new() {
	for DAT in 'geoip' 'geosite'; do
		mv "${TEMPDIR}/$DAT.dat.new" "${WORKDIR}/$DAT.dat"
		# rm "${TEMPDIR}/$DAT.dat.new"
		rm "${TEMPDIR}/$DAT.dat.sha256sum.new"
	done
}

LOG_FILE=/var/log/ssrplus.log
echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

EXIT(){
	rm /var/run/update_dat 2>/dev/null
	rm -rf $TEMPDIR 2>/dev/null
	[ "$1" != "0" ] && echolog "MosDNS更新失败，代码：$1" && touch /var/run/update_dat_error && echo $1 > /var/run/update_dat_error
	[ "$1" == "0" ] && echolog "MosDNS更新成功"
	exit $1
}

main(){
	touch /var/run/update_dat
	rm -rf $TEMPDIR 2>/dev/null
	rm /var/run/update_dat_error 2>/dev/null
	mkdir $TEMPDIR

	download_geoip
	download_geosite
	rename_new
	echo -n 0
	EXIT 0
}

main
