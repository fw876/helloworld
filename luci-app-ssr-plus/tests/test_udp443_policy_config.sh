#!/bin/bash
# Test the generated-config decision and the actual nft cache invalidation.
set -eu
package=$(cd "$(dirname "$0")/.." && pwd)
rules=$package/root/usr/bin/ssr-rules
init=$package/root/etc/init.d/shadowsocksr
eval "$(awk '$0 == "udp443_action() {" {copy=1} copy {print} copy && /^}$/ {exit}' "$init")"
invalidation=$(awk '/^\t\tif \[ "\$UDP443_POLICY"/{copy=1} copy{print} copy && /^\t\tfi$/{exit}' "$rules")
test -n "$invalidation"
test_dir=$(mktemp -d)
trap 'rm -f "$test_dir/config.json" "$test_dir/rules.nft"; rmdir "$test_dir"' EXIT

# These are generated outbound objects, not UCI preferences. A non-Xray
# launch passes no config, so stale Vision/Mux preferences cannot reject QUIC.
count=0
while IFS='|' read -r expected outbound; do
	printf '{"outbounds":[%s]}\n' "$outbound" > "$test_dir/config.json"
	actual=$(udp443_action "$test_dir/config.json")
	if [ "$actual" != "$expected" ]; then
		echo "FAIL: expected $expected, got $actual for $outbound"
		exit 1
	fi
	count=$((count + 1))
done <<'CASES'
proxy|{}
proxy|{"protocol":"vmess"}
proxy|{"protocol":"trojan"}
proxy|{"protocol":"shadowsocks"}
proxy|{"protocol":"vless","settings":{"vnext":[{"users":[{}]}]}}
reject|{"protocol":"vless","settings":{"vnext":[{"users":[{"flow":"xtls-rprx-vision"}]}]}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision-udp443"}}
proxy|{"protocol":"vmess","settings":{"flow":"xtls-rprx-vision"}}
proxy|{"protocol":"vmess","mux":{"enabled":false,"xudpProxyUDP443":"reject"}}
reject|{"protocol":"vmess","mux":{"enabled":true}}
reject|{"protocol":"vmess","mux":{"enabled":true,"xudpProxyUDP443":""}}
reject|{"protocol":"vmess","mux":{"enabled":true,"xudpProxyUDP443":"reject","concurrency":-1,"xudpConcurrency":-1}}
proxy|{"protocol":"vmess","mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":-1,"xudpConcurrency":16}}
proxy|{"protocol":"vmess","mux":{"enabled":true,"xudpProxyUDP443":"skip"}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":false,"xudpProxyUDP443":"allow","xudpConcurrency":16}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"reject","xudpConcurrency":16}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":-1,"xudpConcurrency":16}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":8,"xudpConcurrency":0}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"allow"}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":-1,"xudpConcurrency":0}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":8,"xudpConcurrency":-1}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision"},"mux":{"enabled":true,"xudpProxyUDP443":"skip","xudpConcurrency":16}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision-udp443"},"mux":{"enabled":true,"xudpProxyUDP443":"skip","xudpConcurrency":16}}
reject|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision-udp443"},"mux":{"enabled":true,"xudpProxyUDP443":"reject"}}
proxy|{"protocol":"vless","settings":{"flow":"xtls-rprx-vision-udp443"},"mux":{"enabled":true,"xudpProxyUDP443":"allow","concurrency":-1,"xudpConcurrency":-1}}
CASES
test "$(udp443_action '')" = proxy
ARG_UDP_RULES=-y
test "$(udp443_action '')" = reject
ARG_UDP_RULES=
test "$(udp443_action "$test_dir/missing.json")" = proxy
printf 'invalid json\n' > "$test_dir/config.json"
test "$(udp443_action "$test_dir/config.json")" = proxy
echo "PASS: $count generated-config cases plus non-Xray/missing/malformed defaults"

# Wiring contracts: reset on every load and record only actual UDP Xray
# launches (shared TCP/UDP configs and separate UDP configs, including shadowtls).
test "$(grep -c 'UDP_XRAY_CONFIG=\$udp_config_file' "$init")" = 2
test "$(grep -Fc 'case "$mode" in *udp*) UDP_XRAY_CONFIG=$tcp_config_file ;; esac' "$init")" = 2
awk '$0 == "load_config() {" {copy=1} copy {print} copy && /^}$/ {exit}' "$init" | grep -q 'UDP_XRAY_CONFIG=""'
grep -Fq -- '-Q "$(udp443_action "$UDP_XRAY_CONFIG")"' "$init"
! grep -q 'udp443_policy' "$package/luasrc/model/cbi/shadowsocksr/advanced.lua"
! grep -q 'get shadowsocksr.@global\[0\].udp443_policy' "$rules"

# Exercise the actual internal CLI parser without any top-level firewall setup.
parser=$(awk '/^while getopts / {copy=1} copy {print} copy && /^done$/ {exit}' "$rules")
test -n "$parser"
for input in proxy reject legacy invalid 'reject; false'; do
	if actual=$(
		UDP443_POLICY=proxy
		usage() { exit "$1"; }
		set -- -Q "$input"
		eval "$parser"
		printf '%s' "$UDP443_POLICY"
	); then
		case "$input" in proxy|reject) test "$actual" = "$input" ;; *) exit 1 ;; esac
	else
		test "$?" = 2
		case "$input" in proxy|reject) exit 1 ;; esac
	fi
done

NFTABLES_RULES_FILE="$test_dir/rules.nft"
ENABLE_FAKE_IP_CHANGED=0 TPROXY_HAS_VALUE=1 LAST_HAS_VALUE=1
PROXY_HAS_VALUE=0 LAST_PROXY_HAS_VALUE=0 ANY_IP_LIST_CHANGED=0
loger() { :; }
for before in '' legacy proxy reject; do
	for after in proxy reject; do
		LAST_UDP443_POLICY=$before UDP443_POLICY=$after
		FORCE_RECREATE=0 PERSISTENCE_EXISTS=0
		printf '# test fixture\n' > "$NFTABLES_RULES_FILE"
		eval "$invalidation"
		if [ "$before" = "$after" ]; then
			test "$FORCE_RECREATE" = 0 && test "$PERSISTENCE_EXISTS" = 1
		else
			test "$FORCE_RECREATE" = 1 && test ! -e "$NFTABLES_RULES_FILE"
		fi
	done
done
echo 'PASS: startup wiring, internal CLI validation and all 8 nft action-cache transitions'
