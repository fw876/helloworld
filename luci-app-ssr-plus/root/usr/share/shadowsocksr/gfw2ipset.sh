#!/bin/sh

. $IPKG_INSTROOT/etc/init.d/shadowsocksr

check_run_environment

case "$USE_TABLES" in
	nftables)
		nft_support=1
		echolog "gfw2ipset: Using nftables"
		;;
	iptables)
		nft_support=0
		echolog "gfw2ipset: Using iptables"
		;;
	*)
		echolog "ERROR: No supported firewall backend detected"
		exit 1
		;;
esac
mkdir -p $TMP_DNSMASQ_PATH

run_mode=$(normalize_run_mode)

cp -rf /etc/ssrplus/gfw_list.conf $TMP_DNSMASQ_PATH/
cp -rf /etc/ssrplus/gfw_base.conf $TMP_DNSMASQ_PATH/

for conf_file in gfw_base.conf gfw_list.conf; do
	conf="$TMP_DNSMASQ_PATH/$conf_file"
	[ -f "$conf" ] || continue

	if [ "$run_mode" = "gfw" ]; then
		if [ "$nft_support" = "1" ]; then
			# gfw + nft：ipset → nftset
			sed -i 's|ipset=/\([^/]*\)/\([^[:space:]]*\)|nftset=/\1/inet#ss_spec#\2|g' "$conf"
		fi
	else
		# 非 gfw：无条件清理所有分流引用
		# sed -i '/^[[:space:]]*\(ipset=\|nftset=\)/d' "$conf"
		sed -i '/^[[:space:]]*ipset=/d' "$conf"
	fi
done
rm -f $TMP_DNSMASQ_PATH/netflix_forward.conf

# 此处使用 for 方式读取 防止 /etc/ssrplus/ 目录下的 black.list white.list deny.list 等2个或多个文件一行中存在空格 比如:# abc.com 而丢失：server
# Optimize: Batch filter using grep
for list_file in /etc/ssrplus/black.list /etc/ssrplus/white.list /etc/ssrplus/deny.list; do
	if [ -s "$list_file" ]; then
		grep -vE '^\s*#|^\s*$' "$list_file" > "${list_file}.clean"
		if [ -s "${list_file}.clean" ]; then
			for target_file in "$TMP_DNSMASQ_PATH/gfw_list.conf" "$TMP_DNSMASQ_PATH/gfw_base.conf"; do
				if [ -f "$target_file" ]; then
					grep -v -F -f "${list_file}.clean" "$target_file" > "${target_file}.tmp"
					mv "${target_file}.tmp" "$target_file"
				fi
			done
		fi
		rm -f "${list_file}.clean"
	fi
done

# 此处直接使用 cat 因为有 sed '/#/d' 删除了 数据
if [ "$nft_support" = "1" ]; then
	cat /etc/ssrplus/black.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$dns_port\nnftset=\/&\/inet#ss_spec#blacklist/" >$TMP_DNSMASQ_PATH/blacklist_forward.conf
	cat /etc/ssrplus/white.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1\nnftset=\/&\/inet#ss_spec#whitelist/" >$TMP_DNSMASQ_PATH/whitelist_forward.conf
elif [ "$nft_support" = "0" ]; then
	cat /etc/ssrplus/black.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$dns_port\nipset=\/&\/blacklist/" >$TMP_DNSMASQ_PATH/blacklist_forward.conf
	cat /etc/ssrplus/white.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1\nipset=\/&\/whitelist/" >$TMP_DNSMASQ_PATH/whitelist_forward.conf
fi
cat /etc/ssrplus/deny.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/address=\/&\//" >$TMP_DNSMASQ_PATH/denylist.conf

if [ "$(uci_get_by_type global adblock 0)" == "1" ]; then
	cp -f /etc/ssrplus/ad.conf $TMP_DNSMASQ_PATH/
	if [ -f "$TMP_DNSMASQ_PATH/ad.conf" ]; then
		for list_file in /etc/ssrplus/black.list /etc/ssrplus/white.list /etc/ssrplus/deny.list; do
			if [ -s "$list_file" ]; then
				grep -vE '^\s*#|^\s*$' "$list_file" > "${list_file}.clean"
				if [ -s "${list_file}.clean" ]; then
					grep -v -F -f "${list_file}.clean" "$TMP_DNSMASQ_PATH/ad.conf" > "$TMP_DNSMASQ_PATH/ad.conf.tmp"
					mv "$TMP_DNSMASQ_PATH/ad.conf.tmp" "$TMP_DNSMASQ_PATH/ad.conf"
				fi
				rm -f "${list_file}.clean"
			fi
		done
	fi
else
	rm -f $TMP_DNSMASQ_PATH/ad.conf
fi
