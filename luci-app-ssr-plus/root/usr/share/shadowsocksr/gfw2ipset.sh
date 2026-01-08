#!/bin/sh

. $IPKG_INSTROOT/etc/init.d/shadowsocksr

if command -v nft >/dev/null 2>&1; then
    nft_support=1
fi

netflix() {
	if [ -f "$TMP_DNSMASQ_PATH/gfw_list.conf" ] && [ -s /etc/ssrplus/netflix.list ]; then
		grep -vE '^\s*#|^\s*$' /etc/ssrplus/netflix.list > /tmp/ssrplus_netflix.list.clean
		if [ -s /tmp/ssrplus_netflix.list.clean ]; then
			grep -v -F -f /tmp/ssrplus_netflix.list.clean "$TMP_DNSMASQ_PATH/gfw_list.conf" > "$TMP_DNSMASQ_PATH/gfw_list.conf.tmp"
			mv "$TMP_DNSMASQ_PATH/gfw_list.conf.tmp" "$TMP_DNSMASQ_PATH/gfw_list.conf"
			if [ -f "$TMP_DNSMASQ_PATH/gfw_base.conf" ]; then
				grep -v -F -f /tmp/ssrplus_netflix.list.clean "$TMP_DNSMASQ_PATH/gfw_base.conf" > "$TMP_DNSMASQ_PATH/gfw_base.conf.tmp"
				mv "$TMP_DNSMASQ_PATH/gfw_base.conf.tmp" "$TMP_DNSMASQ_PATH/gfw_base.conf"
			fi
		fi
		rm -f /tmp/ssrplus_netflix.list.clean
	fi
	if [ "$nft_support" = "1" ]; then
		# 移除 ipset
		cat /etc/ssrplus/netflix.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$1\nnftset=\/&\/inet#ss_spec#netflix/" >$TMP_DNSMASQ_PATH/netflix_forward.conf
	else
		cat /etc/ssrplus/netflix.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$1\nipset=\/&\/netflix/" >$TMP_DNSMASQ_PATH/netflix_forward.conf
	fi
}
mkdir -p $TMP_DNSMASQ_PATH
if [ "$(uci_get_by_type global run_mode router)" == "oversea" ]; then
	cp -rf /etc/ssrplus/oversea_list.conf $TMP_DNSMASQ_PATH/
else
	cp -rf /etc/ssrplus/gfw_list.conf $TMP_DNSMASQ_PATH/
	cp -rf /etc/ssrplus/gfw_base.conf $TMP_DNSMASQ_PATH/
fi

if [ "$nft_support" = "1" ]; then
	# 移除 ipset 指令
	for conf_file in gfw_base.conf gfw_list.conf; do
		if [ -f "$TMP_DNSMASQ_PATH/$conf_file" ]; then
			sed -i 's|ipset=/\([^/]*\)/\([^[:space:]]*\)|nftset=/\1/inet#ss_spec#\2|g' "$TMP_DNSMASQ_PATH/$conf_file"
		fi
	done
fi

if [ "$(uci_get_by_type global netflix_enable 0)" == "1" ]; then
	# 只有开启 NetFlix分流 才需要取值
	SHUNT_SERVER=$(uci_get_by_type global netflix_server nil)
else
	# 没有开启 设置为 nil
	SHUNT_SERVER=nil
fi
case "$SHUNT_SERVER" in
nil)
	rm -f $TMP_DNSMASQ_PATH/netflix_forward.conf
	;;
$(uci_get_by_type global global_server nil) | $switch_server | same)
	netflix $dns_port
	;;
*)
	netflix $tmp_shunt_dns_port
	;;
esac

# 此处使用while方式读取 防止 /etc/ssrplus/ 目录下的 black.list white.list deny.list 等2个或多个文件一行中存在空格 比如:# abc.com 而丢失：server
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
else
	cat /etc/ssrplus/black.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$dns_port\nipset=\/&\/blacklist/" >$TMP_DNSMASQ_PATH/blacklist_forward.conf
	cat /etc/ssrplus/white.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1\nipset=\/&\/whitelist/" >$TMP_DNSMASQ_PATH/whitelist_forward.conf
fi
cat /etc/ssrplus/deny.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/address=\/&\//" >$TMP_DNSMASQ_PATH/denylist.conf

if [ "$(uci_get_by_type global adblock 0)" == "1" ]; then
	cp -f /etc/ssrplus/ad.conf $TMP_DNSMASQ_PATH/
	if [ -f "$TMP_DNSMASQ_PATH/ad.conf" ]; then
		for list_file in /etc/ssrplus/black.list /etc/ssrplus/white.list /etc/ssrplus/deny.list /etc/ssrplus/netflix.list; do
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
