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

# 此处使用 for 方式读取 防止 /etc/ssrplus/ 目录下的 black.list white.list deny.list 等2个或多个文件一行中存在空格 比如:# abc.com 而丢失：server
# Optimize: Batch filter using grep
for list_file in /etc/ssrplus/black.list /etc/ssrplus/white.list /etc/ssrplus/deny.list; do
	if [ -s "$list_file" ]; then
		# 清理注释和空行
		grep -vE '^\s*#|^\s*$' "$list_file" | sed 's/\r//g' > "${list_file}.clean"
		if [ -s "${list_file}.clean" ]; then
			for target_file in "$TMP_DNSMASQ_PATH/gfw_list.conf" "$TMP_DNSMASQ_PATH/gfw_base.conf"; do
				[ -f "$target_file" ] || continue
				tmp_file="${target_file}.tmp"
				awk -v list="${list_file}.clean" '
				BEGIN {
					while ((getline line < list) > 0) {
						gsub(/\r/, "", line)
						if (line != "") {
							domain[line] = 1
							# 同时支持 *.domain
							domain["*." line] = 1
						}
					}
					close(list)
				}
				{
					# 提取 server=/domain/xxx
					if (match($0, /^server=\/([^\/]+)\//, m)) {
						if (m[1] in domain) next
					}
					# 提取 ipset=/domain/xxx
					if (match($0, /^ipset=\/([^\/]+)\//, m)) {
						if (m[1] in domain) next
					}
					print
				}
				' "$target_file" > "$tmp_file"
				mv "$tmp_file" "$target_file"
			done
		fi
		rm -f "${list_file}.clean"
	fi
done

# 此处直接使用 cat 因为有 sed '/#/d' 删除了 数据
if [ "$nft_support" = "1" ]; then
	sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e "s/.*/server=\/&\/127.0.0.1#$dns_port\nnftset=\/&\/inet#ss_spec#blacklist/" /etc/ssrplus/black.list > "$TMP_DNSMASQ_PATH/blacklist_forward.conf"
	sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e "s/.*/nftset=\/&\/4#inet#ss_spec#whitelist/" /etc/ssrplus/white.list > "$TMP_DNSMASQ_PATH/whitelist_forward.conf"
elif [ "$nft_support" = "0" ]; then
	sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e "s/.*/server=\/&\/127.0.0.1#$dns_port\nipset=\/&\/blacklist/" /etc/ssrplus/black.list > "$TMP_DNSMASQ_PATH/blacklist_forward.conf"
	sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e "s/.*/ipset=\/&\/whitelist/" /etc/ssrplus/white.list > "$TMP_DNSMASQ_PATH/whitelist_forward.conf"
fi

sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e "s/.*/address=\/&\//" /etc/ssrplus/deny.list > "$TMP_DNSMASQ_PATH/denylist.conf"

if [ "$(uci_get_by_type global adblock 0)" == "1" ]; then
	cp -f /etc/ssrplus/ad.conf "$TMP_DNSMASQ_PATH/"
	if [ -f "$TMP_DNSMASQ_PATH/ad.conf" ]; then
		for list_file in /etc/ssrplus/black.list /etc/ssrplus/white.list /etc/ssrplus/deny.list; do
			if [ -s "$list_file" ]; then
				# 清理注释 & 空行
				grep -vE '^\s*#|^\s*$' "$list_file" | sed 's/\r//g' > "${list_file}.clean"
				if [ -s "${list_file}.clean" ]; then
					tmp_file="$TMP_DNSMASQ_PATH/ad.conf.tmp"
					awk -v list="${list_file}.clean" '
					BEGIN {
						while ((getline line < list) > 0) {
							gsub(/\r/, "", line)
							if (line != "") {
								domain[line] = 1
								# 支持泛域名
								domain["*." line] = 1
							}
						}
						close(list)
					}
					{
						keep = 1
						# 精确匹配 server=/domain/
						if (match($0, /^server=\/([^\/]+)\//, m)) {
							if (m[1] in domain) keep = 0
						}
						# 精确匹配 ipset=/domain/
						if (match($0, /^ipset=\/([^\/]+)\//, m)) {
							if (m[1] in domain) keep = 0
						}
						if (keep) print
					}
					' "$TMP_DNSMASQ_PATH/ad.conf" > "$tmp_file"
					mv "$tmp_file" "$TMP_DNSMASQ_PATH/ad.conf"
				fi
				rm -f "${list_file}.clean"
			fi
		done
	fi
else
	rm -f "$TMP_DNSMASQ_PATH/ad.conf"
fi
