backup=`ip6tables -t filter -S zone_lan_forward | grep -v 'zone_wan_dest_REJECT\|-N' | tr '\n' '\0' | xargs -0 -n1 echo ip6tables`
ip6tables -t filter -F zone_lan_forward
eval "$backup"

ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2400:cb00::/32
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2606:4700::/32
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2803:f800::/32
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2405:b500::/32
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2405:8100::/32
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2a06:98c0::/29
ip6tables -I zone_lan_forward -j zone_wan_dest_REJECT -d 2c0f:f248::/32
