#!/bin/sh
[ -f "$1" ] && china_ip=$1

if command -v nft >/dev/null 2>&1; then
    # 确保表和集合存在
    nft add table inet ss_spec 2>/dev/null
    nft add set inet ss_spec china '{ type ipv4_addr; flags interval; auto-merge; }' 2>/dev/null
    nft flush set inet ss_spec china 2>/dev/null

    # 批量导入
    if [ -f "${china_ip:=/etc/ssrplus/china_ssr.txt}" ]; then
        echo "批量导入中国IP列表..."
        nft add element inet ss_spec china { $(tr '\n' ',' < "${china_ip}" | sed 's/,$//') } 2>/dev/null
        echo "中国IP集合导入完成"
    fi
else
    ipset -! flush china 2>/dev/null
    ipset -! -R <<-EOF || exit 1
        create china hash:net
        $(cat ${china_ip:=/etc/ssrplus/china_ssr.txt} | sed -e "s/^/add china /")
EOF
fi
