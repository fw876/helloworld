ip6tables -D FORWARD -m set --match-set blockipv6 dst -j REJECT 2>/dev/null
ipset -X blockipv6
ipset -N blockipv6 hash:net family inet6
ip6tables -I FORWARD -m set --match-set blockipv6 dst -j REJECT
