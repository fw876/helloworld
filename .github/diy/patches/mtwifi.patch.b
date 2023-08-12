--- a/luci-app-mtwifi/luasrc/view/admin_mtk/mtk_wifi_dev_cfg.htm
+++ b/luci-app-mtwifi/luasrc/view/admin_mtk/mtk_wifi_dev_cfg.htm
@@ -472,7 +472,7 @@
     }
 
     function getCountryRegionList(mode) {
-        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_country_region_list")%>', 'mode='+mode,
+        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_country_region_list")%>', { "mode" : mode },
             function(x)
             {
                 //console.log(x);
@@ -497,7 +497,7 @@
     }
 
     function getChannelList(mode, country_region) {
-        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_channel_list")%>', 'mode='+mode+'&country_region='+country_region,
+        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_channel_list")%>', { "mode" : mode, "country_region" : country_region },
             function(x)
             {
                 console.log(x);
@@ -616,7 +616,7 @@
         mode = mode.value*1;
 
         var cr = GetCountryRegion(mode);
-        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_5G_2nd_80Mhz_channel_list")%>', 'ch_cur='+ch+'&country_region='+cr,
+        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_5G_2nd_80Mhz_channel_list")%>', { "ch_cur" : ch, "country_region" : cr },
             function(x)
             {
                 //console.log(x);
@@ -658,7 +658,7 @@
         mode = mode.value*1;
 
         var cr = GetCountryRegion(mode);
-        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_HT_ext_channel_list")%>', 'ch_cur='+ch+'&country_region='+cr,
+        XHR.get('<%=luci.dispatcher.build_url("admin", "network", "wifi", "get_HT_ext_channel_list")%>', { "ch_cur" : ch, "country_region" : cr },
             function(x)
             {
                 console.log(x);

--- a/luci-app-mtwifi/luasrc/view/admin_mtk/mtk_wifi_overview.htm
+++ b/luci-app-mtwifi/luasrc/view/admin_mtk/mtk_wifi_overview.htm
@@ -31,7 +31,7 @@ <h2><a name="content">无线概况</a></h2>
             <tbody>
                 <tr>
                     <td style="width:34px">
-                        <img src="/luci-static/resources/icons/wifi_big.png" style="float:left; margin-right:10px" />
+                        <img src="/luci-static/resources/icons/wifi.png" style="float:left; margin-right:10px" />
                     </td>
                     <td colspan="2" style="text-align:left">
                         <big><strong title="<%=dev.profile%>"> Generic Mediatek <%=dev.devname%></strong></big>
