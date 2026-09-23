#!/bin/bash
# Integration test. Run as root on Linux with bash, python3, iproute2,
# iptables/ipset, nftables and their TPROXY modules. No host rules are changed:
# every case runs in a fresh network namespace, with a nested client namespace.
set -eu
script=$(readlink -f "$0")
rules=${SSR_RULES:-$(dirname "$script")/../root/usr/bin/ssr-rules}

if [ "${1:-}" != --inside ]; then
	for backend in iptables nft; do
		for policy in proxy reject; do
			for scenario in direct china bypass-client forced-client game fake-ip fake-ip-global fake-ip-allow fake-ip-block fake-ip-global-allow fake-ip-global-block fake-ip-ac-exclude fake-ip-global-ac-exclude fake-ip-interface-exclude fake-ip-excluded-port fake-ip-global-excluded-port fake-ip-dns fake-ip-other-udp fake-ip-split-port fake-ip-tcp excluded-port dns other-udp tcp lan-ac-exclude interface-exclude restore cleanup; do
				unshare --net "$script" --inside "$backend" "$policy" router "$scenario"
			done
			for mode in router gfw all; do
				unshare --net "$script" --inside "$backend" "$policy" "$mode" proxy
				unshare --net "$script" --inside "$backend" "$policy" "$mode" fake-ip
			done
		done
		unshare --net "$script" --inside "$backend" reject gfw gfw-unmatched
		for scenario in no-relay no-relay-disabled no-relay-direct no-relay-china no-relay-bypass no-relay-lan-exclude no-relay-interface-exclude no-relay-excluded-port no-relay-other-udp fake-ip-no-relay fake-ip-no-relay-443 fake-ip-no-relay-ac-exclude fake-ip-no-relay-excluded-port; do
			unshare --net "$script" --inside "$backend" reject router "$scenario"
		done
	done
	exit 0
fi

backend=$2 UDP443_POLICY=$3 RUNMODE=$4 scenario=$5
test_dir=$(mktemp -d)
client_pid= listener_pid=
cleanup() {
	[ -z "$listener_pid" ] || kill "$listener_pid" 2>/dev/null || :
	[ -z "$client_pid" ] || kill "$client_pid" 2>/dev/null || :
	[ -z "$listener_pid" ] || wait "$listener_pid" 2>/dev/null || :
	[ -z "$client_pid" ] || wait "$client_pid" 2>/dev/null || :
	rm -f "$test_dir/listener.log" "$test_dir/include" "$test_dir/rules.nft"
	rmdir "$test_dir"
}
trap cleanup EXIT

# Source only function definitions; do not load the installed init script or
# run ssr-rules' top-level setup. Functions under test are not reimplemented.
for name in ac_rule ac_rule_nft ac_rule_iptables tp_rule quic_reject_nft quic_reject_iptables tp_rule_nft tp_rule_iptables flush_nftables flush_iptables_legacy gen_include_iptables; do
	eval "$(awk -v name="$name" '$0 == name "() {" {copy=1} copy {print} copy && /^}$/ {exit}' "$rules")"
done
gen_spec_iplist() { echo 192.0.2.240; }
set_tproxy_sysctl() { :; }
loger() { :; }
uci() { echo "${Interface:-lan}"; }
NFT=nft IPT='iptables -t nat' ipt='iptables -t mangle'
FWMARK=0x53535250 QUIC_FWMARK=0x51554943 TAG=_SS_SPEC_RULE_
USE_NFT=0; [ "$backend" != nft ] || USE_NFT=1
TPROXY=1 LOCAL_PORT=12345 local_port=12345 SERVER=192.0.2.200 server=192.0.2.200
OUTPUT= DISABLE_UDP_RULES=0
LAN_AC_IP= PROXY_PORTS= EXT_ARGS= Interface=lan ENABLE_FAKE_IP=0
IGNORE_LIST=/nonexistent xhttp_ip=/nonexistent FWI="$test_dir/include"
NFTABLES_RULES_FILE=/nonexistent CLEANUP_PERSISTENCE=0

ip link set lo up
unshare --net sleep 120 & client_pid=$!
for i in {1..100}; do
	[ "$(readlink /proc/$$/ns/net)" = "$(readlink /proc/$client_pid/ns/net)" ] || break
	sleep .01
done
ip link add lan type veth peer name client
ip link set client netns "$client_pid"
ip addr add 203.0.113.1/24 dev lan
ip link set lan up
nsenter -t "$client_pid" -n ip link set lo up
nsenter -t "$client_pid" -n ip addr add 203.0.113.2/24 dev client
nsenter -t "$client_pid" -n ip link set client up
nsenter -t "$client_pid" -n ip route add default via 203.0.113.1
ip link add wan type dummy
ip addr add 198.51.100.1/24 dev wan
ip link set wan up
ip route add default dev wan
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.lan.rp_filter=0 net.ipv4.conf.default.rp_filter=0
# A distinct error identifies direct forwarding, without external traffic.
iptables -A FORWARD -m mark --mark 0x42 -j ACCEPT
iptables -A FORWARD -j REJECT --reject-with icmp-host-unreachable

for name in whitelist blacklist china bplan fplan gmlan gfwlist; do
	ipset create "$name" hash:net
done
dest=192.0.2.123 port=443 protocol=udp expected=$UDP443_POLICY
case "$scenario" in fake-ip*) ENABLE_FAKE_IP=1; dest=198.18.0.10 ;; esac
case "$scenario" in
	fake-ip-global) Interface= ;;
	fake-ip-allow) LAN_AC_IP=w203.0.113.2 ;;
	fake-ip-block) LAN_AC_IP=b203.0.113.99 ;;
	fake-ip-global-allow) Interface=; LAN_AC_IP=w203.0.113.2 ;;
	fake-ip-global-block) Interface=; LAN_AC_IP=b203.0.113.99 ;;
	fake-ip-ac-exclude) LAN_AC_IP=b203.0.113.2; expected=direct ;;
	fake-ip-global-ac-exclude) Interface=; LAN_AC_IP=w203.0.113.99; expected=direct ;;
	fake-ip-interface-exclude) Interface=other; expected=direct ;;
	fake-ip-excluded-port) PROXY_PORTS='-m multiport --dports 8443'; EXT_ARGS=$PROXY_PORTS ;;
	fake-ip-global-excluded-port) Interface=; PROXY_PORTS='-m multiport --dports 8443'; EXT_ARGS=$PROXY_PORTS ;;
	fake-ip-dns) port=53; expected=proxy ;;
	fake-ip-other-udp) port=8443; expected=proxy ;;
	fake-ip-split-port) local_port=12346; port=8443; expected=proxy ;;
	fake-ip-tcp) protocol=tcp; expected=reject ;; # TCP NAT reaches the closed local TCP port.
	fake-ip-no-relay) TPROXY=; port=8443; expected=proxy ;;
	fake-ip-no-relay-443) TPROXY=; DISABLE_UDP_RULES=1; expected=reject ;;
	fake-ip-no-relay-ac-exclude) TPROXY=; DISABLE_UDP_RULES=1; LAN_AC_IP=b203.0.113.2; expected=direct ;;
	fake-ip-no-relay-excluded-port) TPROXY=; DISABLE_UDP_RULES=1; PROXY_PORTS='-m multiport --dports 8443'; EXT_ARGS=$PROXY_PORTS; expected=reject ;;
	excluded-port) PROXY_PORTS='-m multiport --dports 8443'; expected=direct ;;
	dns) port=53; expected=direct ;;
	other-udp) port=8443; expected=proxy ;;
	tcp) protocol=tcp; expected=direct ;;
	lan-ac-exclude) LAN_AC_IP=w203.0.113.99; expected=direct ;;
	interface-exclude) Interface=other; expected=direct ;;
	no-relay) TPROXY=; expected=reject ;;
	no-relay-disabled) TPROXY=; DISABLE_UDP_RULES=1; expected=reject ;;
	no-relay-direct) TPROXY=; expected=direct ;;
	no-relay-china) TPROXY=; expected=direct ;;
	no-relay-bypass) TPROXY=; expected=direct ;;
	no-relay-lan-exclude) TPROXY=; LAN_AC_IP=b203.0.113.2; expected=direct ;;
	no-relay-interface-exclude) TPROXY=; Interface=other; expected=direct ;;
	no-relay-excluded-port) TPROXY=; PROXY_PORTS='-m multiport --dports 8443'; expected=direct ;;
	no-relay-other-udp) TPROXY=; port=8443; expected=direct ;;
	direct|china|bypass-client|gfw-unmatched|cleanup) expected=direct ;;
esac
# Exercise actual NAT setup as well as TPROXY: the old fake-IP REDIRECT
# changed dport 443 before filter rejection, causing the packet to be proxied.
# A distinct TCP-only destination registers NAT hooks in this fresh namespace
# without affecting the UDP probes or reimplementing fake-IP NAT setup.
if [ "$backend" = nft ]; then
	nft add table inet ss_spec
	nft add chain inet ss_spec ss_spec_wan_ac
	nft add rule inet ss_spec ss_spec_wan_ac ip daddr 192.0.2.241 meta l4proto tcp redirect to :12345
else
	iptables -t nat -N SS_SPEC_WAN_AC
	iptables -t nat -A SS_SPEC_WAN_AC -d 192.0.2.241 -p tcp -j REDIRECT --to-ports 12345
fi
ac_rule
tp_rule
add_member() {
	if [ "$backend" = nft ]; then
		nft add element ip ss_spec_mangle "$1" "{ $2 }"
	else
		ipset add "$1" "$2"
	fi
}
case "$scenario" in
	direct|no-relay-direct) add_member whitelist "$dest" ;;
	china|no-relay-china) add_member china "$dest" ;;
	bypass-client|no-relay-bypass) add_member bplan 203.0.113.2 ;;
	forced-client) add_member fplan 203.0.113.2 ;;
	game) add_member gmlan 203.0.113.2 ;;
esac
if [ "$RUNMODE" = gfw ] && [ "$scenario" != gfw-unmatched ]; then
	add_member gfwlist "$dest"
fi

if [ "$scenario" = restore ]; then
	if [ "$backend" = nft ]; then
		nft list table ip ss_spec_mangle > "$test_dir/rules.nft"
		nft delete table ip ss_spec_mangle
		nft -f "$test_dir/rules.nft"
	else
		gen_include_iptables
		sh "$FWI"
	fi
elif [ "$scenario" = cleanup ]; then
	if [ "$backend" = nft ]; then
		if ! flush_nftables; then echo 'FAIL: nft cleanup'; exit 1; fi
	else
		if ! flush_iptables_legacy; then echo 'FAIL: iptables cleanup'; exit 1; fi
	fi
	iptables -C FORWARD -m mark --mark 0x42 -j ACCEPT
	if iptables-save | grep -q SS_SPEC; then echo 'FAIL: residual iptables rules'; exit 1; fi
	if nft list tables | grep -q ss_spec; then echo 'FAIL: residual nftables rules'; exit 1; fi
fi

python3 -u - "$LOCAL_PORT" > "$test_dir/listener.log" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
s.bind(('0.0.0.0', int(sys.argv[1])))
print('ready', flush=True)
while True:
    s.recvfrom(4096)
    print('proxied', flush=True)
PY
listener_pid=$!
for i in {1..100}; do
	grep -q ready "$test_dir/listener.log" && break
	sleep .01
done
result=$(nsenter -t "$client_pid" -n python3 - "$dest" "$port" "$protocol" <<'PY'
import errno, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if sys.argv[3] == 'tcp' else socket.SOCK_DGRAM)
if sys.argv[3] == 'udp':
    s.setsockopt(socket.SOL_IP, 11, 1)  # IP_RECVERR: report soft ICMP errors too
s.settimeout(.4)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.send(b'ssr-policy-test')
    s.recv(4096)
    print('reply')
except OSError as error:
    print({errno.ECONNREFUSED: 'reject', errno.EHOSTUNREACH: 'direct'}.get(error.errno, 'timeout'))
finally:
    s.close()
PY
)
if grep -q proxied "$test_dir/listener.log"; then result=proxy; fi
if [ "$result" != "$expected" ]; then
	echo "FAIL: $backend/$UDP443_POLICY/$RUNMODE/$scenario: expected $expected, got $result"
	ip rule show
	iptables-save
	nft list ruleset
	exit 1
fi
echo "PASS: $backend/$UDP443_POLICY/$RUNMODE/$scenario ($result)"
