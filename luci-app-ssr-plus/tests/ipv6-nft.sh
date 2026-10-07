#!/bin/sh
# Run as root on OpenWrt with the package installed. Rules stay in a new netns.
set -eu
ns="ssr6-check-$$"
tmp=$(mktemp -d)
cleanup() {
	ip netns del "$ns" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM
ip netns add "$ns"
. /usr/share/shadowsocksr/ipv6.sh
uci_get_by_type() { :; }
uci_get_by_name() { :; }
FWMARK=0x53535250
local_port=1234
LOCAL_PORT=301
Interface=""
LAN_AC_IP="w192.0.2.1 2001:db8::1"
WAN_BP_IP="192.0.2.2 2001:db8:1::/64"
WAN_FW_IP="192.0.2.3 2001:db8:2::/64"
LAN_BP_IP="2001:db8::2"
LAN_FP_IP="2001:db8::3"
LAN_GM_IP="2001:db8::4"
count=0
for RUNMODE in gfw router all; do
	for OUTPUT in 0 1 2; do
		for udp in tproxy quic disabled; do
			TPROXY=""
			DISABLE_UDP_RULES=0
			case "$udp" in
			tproxy) TPROXY=2 ;;
			disabled) DISABLE_UDP_RULES=1 ;;
			esac
			for PROXY_PORTS in "" "-m multiport --dports 53,80,443,8000:8100"; do
				ip netns exec "$ns" nft flush ruleset
				ip netns exec "$ns" nft add table inet ss_spec
				ipv6_rules_generate > "$tmp/rules"
				ip netns exec "$ns" nft -f "$tmp/rules"
				# Validate the serialized form used during a firewall reload.
				ip netns exec "$ns" nft list ruleset > "$tmp/snapshot"
				ip netns exec "$ns" nft flush ruleset
				ip netns exec "$ns" nft -f "$tmp/snapshot"
				count=$((count + 1))
			done
		done
	done
done
printf 'PASS: %s IPv6 mode/OUTPUT/UDP/port combinations and snapshot reloads\n' "$count"
