# Inbound TCP congestion control

In **Servers → Edit an Xray node**, the **Inbound TCP congestion control**
selector configures the client-facing transparent-proxy and SOCKS listeners.
It is independent of the existing outbound `custom_tcpcongestion` setting.
Only algorithms reported by `/proc/sys/net/ipv4/tcp_available_congestion_control`
are offered. The control is hidden when Xray is unavailable or Mihomo is selected.

The default is the kernel's system default: no new socket configuration is emitted.
The per-node UCI key is `inbound_tcpcongestion`. Save & Apply uses the existing
service restart path. If the configured algorithm becomes unavailable (for example
after a kernel change), the generator warns and keeps the system default instead
of making the listener fail. No sysctl or kernel module is changed automatically.
UDP-only listeners are not changed. Clearing the selector restores the old output.

Run the generator and CBI declaration regressions from the repository root:

```sh
lua luci-app-ssr-plus/tests/test_inbound_tcpcongestion.lua
lua luci-app-ssr-plus/tests/test_inbound_tcpcongestion_ui.lua
```

The tests work with Lua 5.1 and newer and need no installed LuCI modules.
They execute the actual generator/declaration with mocked UCI/kernel inputs.
They are not a browser rendering test.

An optional fixture uses the router's real LuCI JSON encoder and Xray config
validator without reading production UCI or starting listeners:

```sh
lua luci-app-ssr-plus/tests/inbound_tcpcongestion_fixture.lua \
  luci-app-ssr-plus/root/usr/share/shadowsocksr/gen_config.lua bbr > /tmp/inbound-test.json
xray run -test -config /tmp/inbound-test.json
```

For end-to-end acceptance, select an available algorithm, Save & Apply, verify
the generated listener's `streamSettings.sockopt.tcpcongestion`, and inspect an
actual transparent client socket with `ss -tin`. A config parse alone does not
prove which algorithm an accepted client connection uses.
