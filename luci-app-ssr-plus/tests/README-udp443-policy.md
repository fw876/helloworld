# Proxied UDP/443 policy

**Advanced Settings → Proxied UDP/443 policy** stores the global UCI option
`udp443_policy`. It applies to IPv4 traffic selected for transparent UDP relay:

| Value | Behavior |
| --- | --- |
| `legacy` (default/unset) | Preserve the existing UDP/443 behavior for the selected routing mode. |
| `proxy` | Remove the unconditional UDP/443 drop in router/GFW modes; relay only traffic selected by the existing policy. |
| `reject` | Send ICMP port-unreachable for proxy-selected UDP/443; preserve direct-route exemptions and relay other UDP normally. |

This is a port policy, not packet-level QUIC detection. It affects other protocols
using UDP/443 too. LAN access controls, interface selection, node IPs, whitelist,
bypass clients, China/GFW lists, game/forced clients, proxy ports and fake-IP routing
keep their existing precedence. Different backends' pre-existing classification
differences are not changed here. TCP, DNS and UDP/80 policy are not broadened.

The setting requires transparent UDP relay. It does not enable UDP for TCP-only
nodes. `proxy` does not bypass restrictions in the proxy core: Xray Vision needs
the existing `xtls-rprx-vision-udp443` flow to carry UDP/443, and Mux's existing
`xudpProxyUDP443` option must also permit it when Mux is enabled.

The rejection action is selected at the same points as TPROXY, avoiding a second,
diverging destination list. Mark `0x51554943` is deliberately separate from the
TPROXY mark: packets follow normal routing and are rejected in a filter hook,
not sent through the local TPROXY routing table. The mark is cleared before the
ICMP error is generated. No global ICMP rate limits are changed.

Save & Apply uses the existing restart path. iptables filter hooks are included
in SSR's restore/cleanup lifecycle; cleanup does not remove unrelated filter
mark rules. nftables includes the new chains in its existing table persistence,
and policy changes invalidate the cached ruleset.

## Tests

```sh
lua luci-app-ssr-plus/tests/test_udp443_policy_ui.lua
bash luci-app-ssr-plus/tests/test_udp443_policy_config.sh
sudo luci-app-ssr-plus/tests/test_udp443_policy.sh
```

The integration test needs Linux, bash, Python 3, iproute2, iptables/ipset,
nftables and TPROXY support. Every case runs in a fresh network namespace with
a separate client namespace; no host interfaces, routes or firewall rules are
modified. Documentation-only destination addresses never leave these namespaces.

The suite sends real packets to check each policy in router/GFW/global modes,
direct/China/bypass exemptions, forced/game clients, fake-IP, port/interface
selection, DNS, TCP, other UDP, persistence replay and cleanup. A transparent
UDP listener distinguishes actual relay from a silent drop. An unrelated filter
mark rule must survive cleanup. CI exercises both iptables implementations plus
native nftables.

On hardware, verify an ICMP port-unreachable reaches a LAN client for a selected
destination, a bypass destination still takes the direct path, and TCP fallback
works. Repeated ICMP errors can be rate-limited by the kernel.
