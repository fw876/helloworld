#!/bin/sh
# IPv6 nftables rules, sourced by ssr-rules. DNS sets are shared by TCP and UDP.

# br_netfilter can run inet prerouting before ipv6_rcv() orphans the skb,
# losing the TPROXY socket on bridged LAN ingress. Routed fw4 filtering still
# runs when this bridge-only compatibility hook is disabled.
ipv6_bridge_nf() {
	local knob=/proc/sys/net/bridge/bridge-nf-call-ip6tables
	local saved=/var/run/ssrplus-ipv6-bridge-nf
	[ -f "$knob" ] || return 0
	if [ "$1" = "start" ]; then
		[ -f "$saved" ] || cat "$knob" > "$saved"
		echo 0 > "$knob"
	elif [ -f "$saved" ]; then
		[ "$(cat "$knob")" != "0" ] || cat "$saved" > "$knob"
		rm -f "$saved"
	fi
}

ipv6_policy_route() {
	ipv6_bridge_nf start || return 1
	ip -6 rule show | grep -q "fwmark ${FWMARK}.*lookup 999" ||
		ip -6 rule add fwmark "$FWMARK" table 999 priority 999 || return 1
	ip -6 route replace local ::/0 dev lo table 999
}

ipv6_policy_cleanup() {
	ipv6_bridge_nf stop
	while ip -6 rule del fwmark "$FWMARK" table 999 2>/dev/null; do :; done
	ip -6 route del local ::/0 dev lo table 999 2>/dev/null
	return 0
}

ipv6_set_elements() {
	local setname="$1" address
	shift
	for address in "$@"; do
		case "$address" in
		*:*) printf 'add element inet ss_spec %s { %s }\n' "$setname" "$address" ;;
		esac
	done
}

ipv6_policy_rules() {
	local chain="$1" target="$2"
	cat <<-RULES
		add rule inet ss_spec $chain meta mark 255 return
		add rule inet ss_spec $chain fib daddr type local return
		add rule inet ss_spec $chain ip6 daddr @local6 return
		add rule inet ss_spec $chain ip6 daddr @servers6 return
		add rule inet ss_spec $chain ip6 daddr @blacklist6 goto $target
		add rule inet ss_spec $chain ip6 daddr @whitelist6 return
		add rule inet ss_spec $chain ip6 daddr @whitelist_domain6 return
		add rule inet ss_spec $chain ip6 saddr @fplan6 goto $target
		add rule inet ss_spec $chain ip6 saddr @bplan6 return
	RULES
	case "$RUNMODE" in
	gfw)
		echo "add rule inet ss_spec $chain ip6 daddr @china6 return"
		echo "add rule inet ss_spec $chain ip6 daddr @gfwlist6 goto $target"
		echo "add rule inet ss_spec $chain ip6 saddr @gmlan6 goto $target"
		;;
	router)
		echo "add rule inet ss_spec $chain ip6 daddr @china6 return"
		echo "add rule inet ss_spec $chain goto $target"
		;;
	all) echo "add rule inet ss_spec $chain goto $target" ;;
	esac
}

ipv6_lan_hook() {
	local chain="$1" proto="$2" target="$3" match="" name ifname
	case "${LAN_AC_IP%%${LAN_AC_IP#?}}" in
	w|W) match="ip6 saddr @lan_ac6" ;;
	b|B) match="ip6 saddr != @lan_ac6" ;;
	esac
	if [ -z "$Interface" ]; then
		echo "add rule inet ss_spec $chain meta nfproto ipv6 meta l4proto $proto $match jump $target"
	else
		for name in $Interface; do
			ifname=$(uci -P /var/state -q get "network.$name.ifname")
			[ -n "$ifname" ] || ifname=$(uci -P /var/state -q get "network.$name.device")
			[ -n "$ifname" ] || continue
			echo "add rule inet ss_spec $chain iifname \"$ifname\" meta nfproto ipv6 meta l4proto $proto $match jump $target"
		done
	fi
}

ipv6_rules_generate() {
	local setname sid host ports
	for setname in china6 whitelist6 blacklist6 fplan6 bplan6 gmlan6 lan_ac6 servers6; do
		echo "add set inet ss_spec $setname { type ipv6_addr; flags interval; auto-merge; }"
	done
	for setname in gfwlist6 whitelist_domain6; do
		echo "add set inet ss_spec $setname { type ipv6_addr; }"
	done
	cat <<-'RULES'
		add set inet ss_spec local6 { type ipv6_addr; flags interval; auto-merge; elements = { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b:1::/48, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 }; }
	RULES
	if [ -s /etc/ssrplus/china6_ssr.txt ]; then
		echo 'add element inet ss_spec china6 {'
		sed -e 's/#.*//' -e '/^[[:space:]]*$/d' -e 's/$/,/' /etc/ssrplus/china6_ssr.txt
		echo '}'
	fi
	ipv6_set_elements whitelist6 $WAN_BP_IP
	ipv6_set_elements blacklist6 $WAN_FW_IP
	ipv6_set_elements fplan6 $LAN_FP_IP
	ipv6_set_elements bplan6 $LAN_BP_IP
	ipv6_set_elements gmlan6 $LAN_GM_IP
	ipv6_set_elements lan_ac6 ${LAN_AC_IP#?}
	for sid in "$(uci_get_by_type global global_server)" "$(uci_get_by_type global udp_relay_server)"; do
		host=$(uci_get_by_name "$sid" server)
		host="${host#\[}"
		host="${host%\]}"
		[ -n "$host" ] || continue
		case "$host" in
		*:*) ipv6_set_elements servers6 "$host" ;;
		*) ipv6_set_elements servers6 $(resolveip -6 -t 3 "$host" 2>/dev/null) ;;
		esac
	done
	ports=$(echo "$PROXY_PORTS" | sed 's/-m multiport --dports //; s/:/-/g')
	cat <<-'RULES'
		add chain inet ss_spec ss_spec6_tcp
		add chain inet ss_spec ss_spec6_redirect
		add chain inet ss_spec ss_spec6_prerouting { type nat hook prerouting priority -1; policy accept; }
	RULES
	[ -z "$ports" ] || echo "add rule inet ss_spec ss_spec6_redirect tcp dport != { $ports } return"
	echo "add rule inet ss_spec ss_spec6_redirect meta l4proto tcp counter redirect to :$local_port"
	ipv6_policy_rules ss_spec6_tcp ss_spec6_redirect
	ipv6_lan_hook ss_spec6_prerouting tcp ss_spec6_tcp
	if [ "$OUTPUT" = "1" ] || [ "$OUTPUT" = "2" ]; then
		echo 'add chain inet ss_spec ss_spec6_output { type nat hook output priority -1; policy accept; }'
		if [ "$OUTPUT" = "2" ]; then
			cat <<-'RULES'
				add rule inet ss_spec ss_spec6_output meta mark 255 return
				add rule inet ss_spec ss_spec6_output fib daddr type local return
				add rule inet ss_spec ss_spec6_output ip6 daddr @local6 return
				add rule inet ss_spec ss_spec6_output ip6 daddr @servers6 return
				add rule inet ss_spec ss_spec6_output meta nfproto ipv6 meta l4proto tcp jump ss_spec6_redirect
			RULES
		else
			echo 'add rule inet ss_spec ss_spec6_output meta nfproto ipv6 meta l4proto tcp jump ss_spec6_tcp'
		fi
	fi

	[ "$DISABLE_UDP_RULES" = "1" ] && return 0
	cat <<-'RULES'
		add chain inet ss_spec ss_spec6_udp
		add chain inet ss_spec ss_spec6_udp_proxy
		add chain inet ss_spec ss_spec6_mangle { type filter hook prerouting priority mangle; policy accept; }
		add rule inet ss_spec ss_spec6_mangle udp dport 53 return
	RULES
	if [ -n "$TPROXY" ]; then
		[ -z "$ports" ] || echo "add rule inet ss_spec ss_spec6_udp_proxy udp dport != { $ports } return"
		echo "add rule inet ss_spec ss_spec6_udp_proxy meta l4proto udp counter meta mark set $FWMARK tproxy ip6 to :$LOCAL_PORT accept"
		echo "add rule inet ss_spec ss_spec6_mangle meta nfproto ipv6 meta l4proto udp meta mark $FWMARK jump ss_spec6_udp_proxy"
	else
		echo 'add rule inet ss_spec ss_spec6_udp_proxy udp dport 443 counter drop'
	fi
	ipv6_policy_rules ss_spec6_udp ss_spec6_udp_proxy
	ipv6_lan_hook ss_spec6_mangle udp ss_spec6_udp
	if [ -n "$TPROXY" ] && { [ "$OUTPUT" = "1" ] || [ "$OUTPUT" = "2" ]; }; then
		cat <<-'RULES'
			add chain inet ss_spec ss_spec6_udp_output { type route hook output priority mangle; policy accept; }
			add chain inet ss_spec ss_spec6_udp_mark
			add chain inet ss_spec ss_spec6_udp_local
			add rule inet ss_spec ss_spec6_udp_output udp dport 53 return
			add rule inet ss_spec ss_spec6_udp_output meta nfproto ipv6 meta l4proto udp jump ss_spec6_udp_local
		RULES
		[ -z "$ports" ] || echo "add rule inet ss_spec ss_spec6_udp_mark udp dport != { $ports } return"
		echo "add rule inet ss_spec ss_spec6_udp_mark counter meta mark set $FWMARK return"
		if [ "$OUTPUT" = "2" ]; then
			local RUNMODE=all
		fi
		ipv6_policy_rules ss_spec6_udp_local ss_spec6_udp_mark
	fi
}

ipv6_rules_apply() {
	[ "$USE_NFT" = "1" ] && ipv6_enabled || return 0
	local rules_file
	rules_file=$(mktemp /tmp/ssr-ipv6.XXXXXX) || return 1
	if ! ipv6_rules_generate > "$rules_file" || ! $NFT -f "$rules_file"; then
		rm -f "$rules_file"
		loger 3 "Failed to install IPv6 proxy rules"
		return 1
	fi
	rm -f "$rules_file"
	if [ -n "$TPROXY" ] && [ "$DISABLE_UDP_RULES" != "1" ]; then
		ipv6_policy_route
	fi
}
