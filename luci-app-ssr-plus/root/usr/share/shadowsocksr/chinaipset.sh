#!/bin/sh

. $IPKG_INSTROOT/etc/init.d/shadowsocksr

check_run_environment

# 设置 china_ip 变量并检查文件是否存在
china_ip="${1:-${china_ip:-/etc/ssrplus/china_ssr.txt}}"
[ -f "$china_ip" ] || exit 1

case "$USE_TABLES" in
	nftables)
		skip_inet="${SKIP_INET:-0}"

		case "$skip_inet" in
			1)
				{
					# ss_spec / inet (仅在表和 set 存在时添加)
					if nft list set inet ss_spec china >/dev/null 2>&1; then
						echo "add element inet ss_spec china {"
						grep -vE '^\s*#|^\s*$' "$china_ip" | sed 's/^/  /;s/$/,/'
						echo "}"
					fi
				} | nft -f - || exit 1
				;;
			2)
				{
					# ss_spec_mangle / ip (仅在表和 set 存在时添加)
					if nft list set ip ss_spec_mangle china >/dev/null 2>&1; then
						echo "add element ip ss_spec_mangle china {"
						grep -vE '^\s*#|^\s*$' "$china_ip" | sed 's/^/  /;s/$/,/'
						echo "}"
					fi
				} | nft -f - || exit 1
				;;
			*)
				echolog "chinaipset: invalid SKIP_INET=$skip_inet"
				exit 1
				;;
		esac
		;;
	iptables)
		ipset -! flush china 2>/dev/null
		ipset -! -R <<-EOF || exit 1
			create china hash:net
			$(grep -vE '^\s*#|^\s*$' "$china_ip" | sed 's/^/add china /')
		EOF
		;;
	*)
		echolog "ERROR: No supported firewall backend detected"
		exit 1
		;;
esac
