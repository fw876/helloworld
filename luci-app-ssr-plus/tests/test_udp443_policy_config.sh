#!/bin/bash
# Exercise UCI normalization and the actual nft cache-invalidation branch.
set -eu
rules=$(dirname "$0")/../root/usr/bin/ssr-rules
normalization=$(awk '/^UDP443_POLICY=/{copy=1} copy{print} copy && /^esac$/{exit}' "$rules")
invalidation=$(awk '/^\t\tif \[ "\$UDP443_POLICY"/{copy=1} copy{print} copy && /^\t\tfi$/{exit}' "$rules")
test -n "$normalization" && test -n "$invalidation"
for input in '' legacy proxy reject invalid 'reject; false'; do
	uci() { test "$*" = '-q get shadowsocksr.@global[0].udp443_policy'; printf '%s' "$input"; }
	eval "$normalization"
	expected=legacy
	case "$input" in proxy|reject) expected=$input ;; esac
	test "$UDP443_POLICY" = "$expected"
done

test_dir=$(mktemp -d)
trap 'rm -f "$test_dir/rules.nft"; rmdir "$test_dir"' EXIT
NFTABLES_RULES_FILE="$test_dir/rules.nft"
ENABLE_FAKE_IP_CHANGED=0 TPROXY_HAS_VALUE=1 LAST_HAS_VALUE=1
PROXY_HAS_VALUE=0 LAST_PROXY_HAS_VALUE=0 ANY_IP_LIST_CHANGED=0
loger() { :; }
for before in '' legacy proxy reject; do
	for after in legacy proxy reject; do
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
echo 'PASS: UCI defaults/validation and all 12 nft policy-cache transitions'
