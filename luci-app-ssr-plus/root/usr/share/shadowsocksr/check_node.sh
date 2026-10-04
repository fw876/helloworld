#!/bin/sh
# Test a node with an HTTPS request through a temporary loopback-only SOCKS proxy.
# Exit 0: HTTP 204 received; 1: request failed; 2: probe could not start.

set -u
umask 077

sid="${1:-}"
case "$sid" in
	''|*[!A-Za-z0-9_]) exit 2 ;;
esac
[ "$(uci -q get "shadowsocksr.$sid" 2>/dev/null)" = "servers" ] || exit 2
node_type="$(uci -q get "shadowsocksr.$sid.type" 2>/dev/null || true)"
case "$node_type" in
	anytls|tuic|v2ray) action="$node_type" ;;
	socks5) action=v2ray ;;
	ss|ss-rust) action=ss ;;
	*) exit 2 ;;
esac
for tool in lua mihomo curl flock; do
	command -v "$tool" >/dev/null 2>&1 || exit 2
done

exec 9>/var/lock/ssrplus-node-check.lock
attempt=0
until flock -xn 9; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 20 ] || exit 2
	sleep 1
done
port=10801
netstat -ltn 2>/dev/null | grep -q ":$port " && exit 2
workdir="$(mktemp -d /tmp/ssrplus-node-check.XXXXXX)" || exit 2
probe_pid=""
cleanup() {
	if [ -n "$probe_pid" ]; then
		kill "$probe_pid" 2>/dev/null || true
		# Bound shutdown time so a stuck core cannot retain the probe lock.
		for attempt in 1 2 3; do
			kill -0 "$probe_pid" 2>/dev/null || break
			sleep 1
		done
		if kill -0 "$probe_pid" 2>/dev/null; then
			kill -9 "$probe_pid" 2>/dev/null || true
		fi
		wait "$probe_pid" 2>/dev/null || true
	fi
	rm -rf -- "$workdir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

lua /usr/share/shadowsocksr/clash_yaml.lua "$action" "$sid" \
	"$workdir/config.yaml" "$port" "$port" probe >/dev/null 2>&1 || exit 2
mihomo -t -d "$workdir" -f "$workdir/config.yaml" >/dev/null 2>&1 || exit 2
mihomo -d "$workdir" -f "$workdir/config.yaml" >"$workdir/mihomo.log" 2>&1 &
probe_pid=$!
for attempt in 1 2 3; do
	kill -0 "$probe_pid" 2>/dev/null || exit 2
	netstat -ltn 2>/dev/null | grep -q "127.0.0.1:$port " && break
	sleep 1
done
netstat -ltn 2>/dev/null | grep -q "127.0.0.1:$port " || exit 2

# Probe mode has no authentication and is never exposed to the LAN.
code="$(curl --noproxy "" --socks5-hostname "127.0.0.1:$port" \
	--connect-timeout 3 --max-time 8 -sS -o /dev/null -w '%{http_code}' \
	https://www.gstatic.com/generate_204 2>/dev/null)"
[ "$code" = "204" ]
