--- a/luci-app-cpufreq/root/etc/uci-defaults/10-cpufreq
+++ b/luci-app-cpufreq/root/etc/uci-defaults/10-cpufreq
@@ -64,6 +64,8 @@ case "$DISTRIB_TARGET" in
 			# RK3399
 			uci_write_config 0 schedutil 600000 1608000
 			uci_write_config 4 schedutil 600000 2016000
+		elif [[ "$(board_name)" == *nanopi-r5s ]]; then
+			uci_write_config 0 schedutil 816000 1992000
 		else
 			# RK3328
 			uci_write_config 0 schedutil 816000 1512000

---
 .../root/usr/share/{rpcd => }/luci/menu.d/luci-app-cpufreq.json   | 0
 1 file changed, 0 insertions(+), 0 deletions(-)
 rename luci-app-cpufreq/root/usr/share/{rpcd => }/luci/menu.d/luci-app-cpufreq.json (100%)

diff --git a/luci-app-cpufreq/root/usr/share/rpcd/luci/menu.d/luci-app-cpufreq.json b/luci-app-cpufreq/root/usr/share/luci/menu.d/luci-app-cpufreq.json
similarity index 100%
rename from luci-app-cpufreq/root/usr/share/rpcd/luci/menu.d/luci-app-cpufreq.json
rename to luci-app-cpufreq/root/usr/share/luci/menu.d/luci-app-cpufreq.json

