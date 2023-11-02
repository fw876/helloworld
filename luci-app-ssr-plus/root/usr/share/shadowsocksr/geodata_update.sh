#!/bin/sh

rm -rf /tmp/geo*

#wget --no-check-certificate -q -O /tmp/geoip.dat https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat
wget --no-check-certificate -q -O /tmp/geosite.dat https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat

remove_full_string() {
    temp_file="$(echo "$1" | awk -F '.' '{print $1"-temp."$2}')"
    temp_file2="$(echo "$1" | awk -F '.' '{print $1"-temp2."$2}')"
    cat $1 | grep 'full:' | awk -F 'full:' '{print $2}' > $temp_file
    cat $1 | grep -v 'full:' > $temp_file2
    cat $temp_file $temp_file2 | sort -u | uniq -u > $1
    rm -rf $temp_file $temp_file2
}

clean_up() {
    temp_file="$(echo "$1" | awk -F '.' '{print $1"-temp."$2}')"
    diff $1 $2 | grep '< ' | awk -F '< ' '{print $2}' > $temp_file
    mv $temp_file $1
}

merge_file() {
    temp_file="/tmp/merged"
    cat $1 $2 | sort -u | uniq -u > $temp_file
    mv $temp_file $2
}

if [ -f "/tmp/geosite.dat" ]; then
    #v2dat unpack geosite -o /tmp/ -f cn -f apple-cn -f google-cn -f geolocation-!cn /tmp/geosite.dat
    v2dat unpack geosite -o /tmp/ -f cn -f google-cn -f geolocation-!cn /tmp/geosite.dat
    remove_full_string /tmp/geosite_cn.txt
    #remove_full_string /tmp/geosite_apple-cn.txt
    remove_full_string /tmp/geosite_google-cn.txt
    remove_full_string /tmp/geosite_geolocation-!cn.txt
    clean_up /tmp/geosite_cn.txt /tmp/geosite_google-cn.txt
    merge_file /tmp/geosite_google-cn.txt /tmp/geosite_geolocation-!cn.txt
    mv /tmp/geosite_cn.txt /etc/ssrplus/mosdns-chinadns/geosite_cn.txt
    mv /tmp/geosite_geolocation-!cn.txt /etc/ssrplus/mosdns-chinadns/geosite_geolocation_not_cn.txt
    rm -rf /tmp/geosite*
    echo 111
else
    echo 000
fi
