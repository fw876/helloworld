#!/bin/bash
# Optional Linux netns test with a Mihomo binary. No host networking changes.
set -eu
script=$(readlink -f "$0")
binary=$(readlink -f "${1:?Mihomo binary required}")
profile=$(readlink -f "${2:-$(dirname "$0")/udp443-mihomo.yaml}")
if [ "${3:-}" != --inside ]; then
	exec sudo unshare --net "$script" "$binary" "$profile" --inside
fi
test_dir=$(mktemp -d)
proxy_pid=
cleanup() {
	local status=$?
	[ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || :
	[ -z "$proxy_pid" ] || wait "$proxy_pid" 2>/dev/null || :
	[ "$status" = 0 ] || tail -60 "$test_dir/mihomo.log" 2>/dev/null || :
	rm -f "$test_dir/mihomo.log" "$test_dir/cache.db"
	rmdir "$test_dir"
}
trap cleanup EXIT
ip link set lo up
"$binary" -f "$profile" -d "$test_dir" > "$test_dir/mihomo.log" 2>&1 & proxy_pid=$!
for i in {1..100}; do
	curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
	sleep .05
done
curl -fsS --max-time 2 http://127.0.0.1:9090/version >/dev/null

send_udp() {
	python3 - "$1" <<'PY'
import socket, struct, sys, time
with socket.create_connection(('127.0.0.1', 7890), timeout=2) as control:
    control.sendall(b'\x05\x01\x00')
    assert control.recv(2) == b'\x05\x00'
    control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    reply = control.recv(10)
    assert reply[:4] == b'\x05\x00\x00\x01', reply
    port = struct.unpack('!H', reply[-2:])[0]
    host = sys.argv[1].encode()
    datagram = b'\x00\x00\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', 443) + b'quic-test'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(datagram, ('127.0.0.1', port))
    time.sleep(.3)
PY
}
send_udp foreign.example
grep -Eq 'dial PROXY .*foreign\.example:443' "$test_dir/mihomo.log"
curl -fsS --max-time 2 -X PUT -H 'Content-Type: application/json' -d '{"name":"udp-off"}' \
	http://127.0.0.1:9090/proxies/PROXY >/dev/null
send_udp foreign.example
grep -Eq 'foreign\.example:443.*using REJECT' "$test_dir/mihomo.log"
send_udp local.example
grep -Eq 'dial DIRECT .*local\.example:443|local\.example:443.*using DIRECT' "$test_dir/mihomo.log"
echo 'PASS: Mihomo sends UDP via a capable member, rejects after switching to an incapable member, and keeps direct rules'
