backup=`ip6tables -t filter -S zone_lan_forward | grep -v 'zone_wan_dest_REJECT\|-N' | tr '\n' '\0' | xargs -0 -n1 echo ip6tables`
ip6tables -t filter -F zone_lan_forward
eval "$backup"
