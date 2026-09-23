# Automatic proxied UDP/443 handling

There is no new UI selector or UCI setting. IPv4 traffic selected by the existing
transparent UDP routing rules is proxied by default, including UDP/443. Direct
and domestic destinations keep their existing bypass rules.

When the actual UDP core is Xray, the service reads the generated default
outbound, not saved preferences for an unused core. It derives the action from
the existing per-node **Flow** and **Mux / UDP 443** settings:

| Effective configuration | Proxy-selected UDP/443 |
| --- | --- |
| Non-Xray core, or Xray without a known blocking setting | Proxy normally. |
| Enabled Mux with `xudpProxyUDP443=reject` (also Xray's omitted/empty default) | Reject with ICMP port-unreachable. |
| Plain `xtls-rprx-vision`, without a permitted active Mux/XUDP path | Reject with ICMP port-unreachable. |
| `xtls-rprx-vision-udp443`, without a rejecting Mux policy | Proxy normally. |
| Enabled Mux with `allow` and active XUDP/Mux transport | Proxy normally, including Vision. |
| Mux `skip` | Follow the underlying flow: plain Vision rejects, otherwise proxy. |

This mirrors [Xray's Mux dispatch](https://github.com/XTLS/Xray-core/blob/v26.7.11/app/proxyman/outbound/handler.go)
and [VLESS Vision UDP handling](https://github.com/XTLS/Xray-core/blob/v26.7.11/proxy/vless/outbound/outbound.go).
Unknown or unreadable configs do not trigger guessed rejection. Switching cores
resets the recorded config; separate UDP launches use their own generated config.
The action is passed to `ssr-rules` using internal `-Q proxy|reject`.

This matches the UDP port, not packet-level QUIC detection. Other protocols on
UDP/443 are affected too. It does not enable UDP for TCP-only nodes, alter IPv6,
or change UDP/80 policy. Existing access-control/classification differences
between the firewall backends are outside this change.

## Fake-IP and firewall lifecycle

With TPROXY enabled, fake-IP UDP is intercepted only in mangle. The old NAT
REDIRECT would rewrite destination port 443 before the filter rejection hook,
bypassing rejection; it could also redirect to the TCP relay's port when the
UDP relay uses a different one. Fake-IP still enters the core regardless of
proxy-port restrictions, while retaining interface and LAN access controls.
Ordinary DNS bypass remains intact; fake-IP UDP/53 follows fake-IP interception.
Without TPROXY, fake-IP UDP NAT remains as before. Fake-IP TCP NAT and
router-originated OUTPUT handling are unchanged.

The rejection action is selected at the same points as TPROXY, avoiding a second,
diverging destination list. Mark `0x51554943` is deliberately separate from the
TPROXY mark: packets follow normal routing and are rejected in a filter hook,
not sent through the local TPROXY routing table. The mark is cleared before the
ICMP error is generated. No global ICMP rate limits are changed.

The existing node Save & Apply/restart path recomputes the action. iptables filter hooks are included
in SSR's restore/cleanup lifecycle; cleanup does not remove unrelated filter
mark rules. nftables includes the new chains in its existing table persistence,
and derived-action changes invalidate the cached ruleset.

## Tests

```sh
lua luci-app-ssr-plus/tests/test_udp443_generator.lua
bash luci-app-ssr-plus/tests/test_udp443_policy_config.sh
sudo luci-app-ssr-plus/tests/test_udp443_policy.sh
```

The config test needs bash and jq. The integration test needs Linux, bash,
Python 3, iproute2, iptables/ipset,
nftables and TPROXY support. Every case runs in a fresh network namespace with
a separate client namespace; no host interfaces, routes or firewall rules are
modified. Documentation-only destination addresses never leave these namespaces.

The suite runs the actual NAT access-control and TPROXY setup functions together,
then sends real packets to check both actions in router/GFW/global modes,
direct/China/bypass exemptions, forced/game clients, fake-IP, port/interface
selection, DNS, TCP, other UDP, relay-disabled behavior, persistence replay and cleanup.
Fake-IP cases include all global/interface and LAN allow/block branches, excluded
ports, distinct TCP/UDP relay ports, UDP/53 and preserved TCP NAT. A transparent
UDP listener distinguishes actual relay from a silent drop. An unrelated filter
mark rule must survive cleanup. CI exercises both iptables implementations plus
native nftables. Lua tests exercise the real UCI-to-Xray generator with existing
Flow/Mux fields for shared and separate UDP configs. Config tests cover Vision/Mux
combinations, non-Xray defaults, startup wiring contracts, and cache transitions. They are not a live
core-launch or hardware end-to-end test.

On hardware, verify an ICMP port-unreachable reaches a LAN client for a selected
destination, a bypass destination still takes the direct path, and TCP fallback
works. Repeated ICMP errors can be rate-limited by the kernel.
