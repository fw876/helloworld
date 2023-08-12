--- a/wifidog-wiwiz/Makefile
+++ b/wifidog-wiwiz/Makefile
@@ -21,7 +21,7 @@ define Package/wifidog-wiwiz
   SUBMENU:=Portal
   SECTION:=net
   CATEGORY:=Wiwiz/PinPinWiFi
-  DEPENDS:=+iptables-mod-extra +iptables-mod-ipopt +iptables-mod-nat-extra +libpthread +curl
+  DEPENDS:=+dcc2-wiwiz-nossl +luci-app-eqos +iptables-mod-extra +iptables-mod-ipopt +iptables-mod-nat-extra +iptables-mod-conntrack-extra +iptables-mod-iface +iptables-mod-ipmark +libpthread +curl
   TITLE:=wifidog-wiwiz
   URL:=http://www.wiwiz.com
 endef
