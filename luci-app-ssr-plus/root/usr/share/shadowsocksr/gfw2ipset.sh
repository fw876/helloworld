#!/bin/sh

. $IPKG_INSTROOT/etc/init.d/shadowsocksr

netflix() {
	if [ -f "$TMP_DNSMASQ_PATH/gfw_list.conf" ]; then
		for line in $(cat /etc/ssrplus/netflix.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_list.conf; done
		for line in $(cat /etc/ssrplus/netflix.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_base.conf; done
	fi
	if command -v nft >/dev/null 2>&1; then
		# 移除 ipset
		cat /etc/ssrplus/netflix.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$1/" >$TMP_DNSMASQ_PATH/netflix_forward.conf
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

if command -v nft >/dev/null 2>&1; then
    # 移除 ipset 指令
    for conf_file in gfw_base.conf gfw_list.conf; do
        if [ -f "$TMP_DNSMASQ_PATH/$conf_file" ]; then
            sed -i '/ipset=/d' "$TMP_DNSMASQ_PATH/$conf_file"
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
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_list.conf; done < /etc/ssrplus/black.list
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_base.conf; done < /etc/ssrplus/black.list
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_list.conf; done < /etc/ssrplus/white.list
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_base.conf; done < /etc/ssrplus/white.list
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_list.conf; done < /etc/ssrplus/deny.list
while read line; do sed -i "/$line/d" $TMP_DNSMASQ_PATH/gfw_base.conf; done < /etc/ssrplus/deny.list

# 此处直接使用 cat 因为有 sed '/#/d' 删除了 数据
if command -v nft >/dev/null 2>&1; then
	cat /etc/ssrplus/black.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$dns_port/" >$TMP_DNSMASQ_PATH/blacklist_forward.conf
	cat /etc/ssrplus/white.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1/" >$TMP_DNSMASQ_PATH/whitelist_forward.conf
else
	cat /etc/ssrplus/black.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1#$dns_port\nipset=\/&\/blacklist/" >$TMP_DNSMASQ_PATH/blacklist_forward.conf
	cat /etc/ssrplus/white.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/server=\/&\/127.0.0.1\nipset=\/&\/whitelist/" >$TMP_DNSMASQ_PATH/whitelist_forward.conf
fi
cat /etc/ssrplus/deny.list | sed '/^$/d' | sed '/#/d' | sed "/.*/s/.*/address=\/&\//" >$TMP_DNSMASQ_PATH/denylist.conf

if [ "$(uci_get_by_type global adblock 0)" == "1" ]; then
	cp -f /etc/ssrplus/ad.conf $TMP_DNSMASQ_PATH/
	if [ -f "$TMP_DNSMASQ_PATH/ad.conf" ]; then
		for line in $(cat /etc/ssrplus/black.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/ad.conf; done
		for line in $(cat /etc/ssrplus/white.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/ad.conf; done
		for line in $(cat /etc/ssrplus/deny.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/ad.conf; done
		for line in $(cat /etc/ssrplus/netflix.list); do sed -i "/$line/d" $TMP_DNSMASQ_PATH/ad.conf; done
	fi
else
	rm -f $TMP_DNSMASQ_PATH/ad.conf
fi
