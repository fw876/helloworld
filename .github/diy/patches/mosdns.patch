--- a/luci-app-mosdns/root/etc/hotplug.d/iface/99-mosdns
+++ b/luci-app-mosdns/root/etc/hotplug.d/iface/99-mosdns
@@ -1,2 +1,2 @@
 #!/bin/sh
-[ "$ACTION" = ifup ] && /etc/init.d/mosdns restart
+[[ "$ACTION" = ifup && "$(uci -q get mosdns.mosdns.enabled)" == 1 ]] && /etc/init.d/mosdns restart
