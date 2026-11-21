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

# ============================================================
# IDN（国际化域名）处理
# dnsmasq、nftset、ipset 只识别 punycode（xn-- 格式）。
# 中文域名必须转成 punycode 才能下发，否则 dnsmasq 的
# legal_hostname() 校验会失败并 ret_err("bad address")，
# 整个 dnsmasq 进程退出，导致所有 DNS 解析和代理规则失效。
#
# 若系统无 idn2，会跳过所有非 ASCII 域名（记 WARNING），
# 避免 dnsmasq fatal。
# ============================================================
if command -v idn2 >/dev/null 2>&1; then
	HAVE_IDN2=1
else
	HAVE_IDN2=0
	echolog "gfw2ipset: WARNING idn2 not found, non-ASCII domains in black.list/white.list/deny.list will be SKIPPED (dnsmasq cannot handle them). Install idn2 or use xn-- form."
fi

idn_line() {
	local result non_ascii

	# 有 idn2：转换，失败 fallback 原值
	if [ "$HAVE_IDN2" = "1" ]; then
		result=$(idn2 --quiet "$1" 2>/dev/null)
		if [ -n "$result" ]; then
			printf '%s\n' "$result"
			return
		fi
		printf '%s\n' "$1"
		return
	fi

	# 无 idn2：含非 ASCII 字节的域名必须跳过
	# 否则 dnsmasq 会在 legal_hostname() 校验时直接 exit
	non_ascii=$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\177')
	if [ -n "$non_ascii" ]; then
		echolog "gfw2ipset: SKIP non-ASCII domain '$1' (idn2 not installed, would cause dnsmasq to fail)"
		return
	fi

	# 纯 ASCII 域名原样输出
	printf '%s\n' "$1"
}

# 处理 list 文件：
#   - 去 \r（CRLF）
#   - 去行内注释（domain.com # xxx → domain.com）
#   - trim 首尾空白
#   - 删空行
#   - IDN2 转换（中文域名 → xn--，无 idn2 时跳过非 ASCII）
#   - || [ -n "$line" ] 保证末行无换行符时也被处理
process_list_file() {
	local list_file="$1"
	[ -s "$list_file" ] || return 0
	sed -e 's/\r//g' \
	    -e 's/[[:space:]]*#.*$//' \
	    -e 's/^[[:space:]]*//' \
	    -e 's/[[:space:]]*$//' \
	    -e '/^$/d' "$list_file" |
	while IFS= read -r line || [ -n "$line" ]; do
		idn_line "$line"
	done
}

mkdir -p $TMP_DNSMASQ_PATH
CLEAN_DIR="$TMP_DNSMASQ_PATH/idn-clean"
mkdir -p "$CLEAN_DIR"

# ============================================================
# 预生成所有 list 的 punycode 版本（放在 /tmp，避开只读 fs）
# ============================================================
blacklist_clean="$CLEAN_DIR/black.list.clean"
whitelist_clean="$CLEAN_DIR/white.list.clean"
denylist_clean="$CLEAN_DIR/deny.list.clean"

process_list_file /etc/ssrplus/black.list > "$blacklist_clean"
process_list_file /etc/ssrplus/white.list > "$whitelist_clean"
process_list_file /etc/ssrplus/deny.list  > "$denylist_clean"

echolog "gfw2ipset: IDN2 clean done: black=$(wc -l < "$blacklist_clean"), white=$(wc -l < "$whitelist_clean"), deny=$(wc -l < "$denylist_clean")"

run_mode=$(normalize_run_mode)
gfw_set="4#inet#ss_spec#gfwlist"
black_set="4#inet#ss_spec#blacklist"
white_set="4#inet#ss_spec#whitelist_domain"
if ipv6_enabled; then
	gfw_set="$gfw_set,6#inet#ss_spec#gfwlist6"
	black_set="$black_set,6#inet#ss_spec#blacklist6"
	white_set="$white_set,6#inet#ss_spec#whitelist_domain6"
fi

cp -rf /etc/ssrplus/gfw_list.conf $TMP_DNSMASQ_PATH/
cp -rf /etc/ssrplus/gfw_base.conf $TMP_DNSMASQ_PATH/

for conf_file in gfw_base.conf gfw_list.conf; do
	conf="$TMP_DNSMASQ_PATH/$conf_file"
	[ -f "$conf" ] || continue

	if [ "$run_mode" = "gfw" ]; then
		if [ "$nft_support" = "1" ]; then
			# gfw + nft：ipset → nftset
			sed -i "s|^ipset=/\\([^/]*\\)/gfwlist$|nftset=/\\1/$gfw_set|" "$conf"
		fi
	else
		# 非 gfw：无条件清理所有分流引用
		sed -i '/^[[:space:]]*\(ipset=\|nftset=\)/d' "$conf"
	fi
done

# ============================================================
# 从 gfw_list.conf / gfw_base.conf 中过滤掉用户列表中的域名
# ============================================================
filter_gfw_by_list() {
	local list="$1"
	[ -s "$list" ] || return 0
	for target_file in "$TMP_DNSMASQ_PATH/gfw_list.conf" "$TMP_DNSMASQ_PATH/gfw_base.conf"; do
		[ -f "$target_file" ] || continue
		tmp_file="${target_file}.tmp"
		awk -v list="$list" '
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
			if ($0 ~ /^server=\//) {
				split($0, m, "/")
				if (m[2] in domain) next
			}
			# 提取 ipset=/domain/xxx
			if ($0 ~ /^(ipset|nftset)=\//) {
				split($0, m, "/")
				if (m[2] in domain) next
			}
			print
		}
		' "$target_file" > "$tmp_file"
		mv "$tmp_file" "$target_file"
	done
}

filter_gfw_by_list "$blacklist_clean"
filter_gfw_by_list "$whitelist_clean"
filter_gfw_by_list "$denylist_clean"

# ============================================================
# 生成 blacklist_forward.conf / whitelist_forward.conf / denylist.conf
# 源文件是 .clean（已 IDN2 转换，纯 ASCII）
# ============================================================
if [ "$nft_support" = "1" ]; then
	sed -e "s/.*/server=\/&\/127.0.0.1#$dns_port\nnftset=\/&\/$black_set/" "$blacklist_clean" > "$TMP_DNSMASQ_PATH/blacklist_forward.conf"
	sed -e "s/.*/nftset=\/&\/$white_set/" "$whitelist_clean" > "$TMP_DNSMASQ_PATH/whitelist_forward.conf"
elif [ "$nft_support" = "0" ]; then
	sed -e "s/.*/server=\/&\/127.0.0.1#$dns_port\nipset=\/&\/blacklist/" "$blacklist_clean" > "$TMP_DNSMASQ_PATH/blacklist_forward.conf"
	sed -e "s/.*/ipset=\/&\/whitelist/" "$whitelist_clean" > "$TMP_DNSMASQ_PATH/whitelist_forward.conf"
fi

sed -e "s/.*/address=\/&\//" "$denylist_clean" > "$TMP_DNSMASQ_PATH/denylist.conf"

# ============================================================
# ad.conf 过滤
# ============================================================
if [ "$(uci_get_by_type global adblock 0)" == "1" ]; then
	cp -f /etc/ssrplus/ad.conf "$TMP_DNSMASQ_PATH/"
	if [ -f "$TMP_DNSMASQ_PATH/ad.conf" ]; then
		for list in "$blacklist_clean" "$whitelist_clean" "$denylist_clean"; do
			[ -s "$list" ] || continue
			tmp_file="$TMP_DNSMASQ_PATH/ad.conf.tmp"
			awk -v list="$list" '
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
				if ($0 ~ /^server=\//) {
					split($0, m, "/")
					if (m[2] in domain) keep = 0
				}
				# 精确匹配 ipset=/domain/
				if ($0 ~ /^(ipset|nftset)=\//) {
					split($0, m, "/")
					if (m[2] in domain) keep = 0
				}
				if (keep) print
			}
			' "$TMP_DNSMASQ_PATH/ad.conf" > "$tmp_file"
			mv "$tmp_file" "$TMP_DNSMASQ_PATH/ad.conf"
		done
	fi
else
	rm -f "$TMP_DNSMASQ_PATH/ad.conf"
fi

# ============================================================
# 清理临时文件
# ============================================================
rm -rf "$CLEAN_DIR"
