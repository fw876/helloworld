#!/bin/sh
# /usr/share/shadowsocksr/test.sh

CONFIG="shadowsocksr"
LOCK_PATH=/tmp/lock
TMP_PATH=/var/etc/ssrplus

uci_get_by_name() {
	local ret=$(uci -q get $CONFIG.$1.$2 2>/dev/null)
	echo "${ret:=$3}"
}

uci_get_by_type() {
	local ret=$(uci -q get $CONFIG.@$1[0].$2 2>/dev/null)
	echo "${ret:=$3}"
}

check_port_exists() {
	local port=$1
	local protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	local result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

set_cache_var() {
	local key="${1}"
	shift 1
	local val="$@"
	[ -n "${key}" ] && [ -n "${val}" ] && {
		sed -i "/${key}=/d" $TMP_PATH/var >/dev/null 2>&1
		echo "${key}=\"${val}\"" >> $TMP_PATH/var
		eval ${key}=\"${val}\"
	}
}

get_cache_var() {
	local key="${1}"
	[ -n "${key}" ] && [ -s "$TMP_PATH/var" ] && {
		echo $(cat $TMP_PATH/var | grep "^${key}=" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}')
	}
}

#uci_get_by_port() {
#    local port=$1
#    while netstat -tuln 2>/dev/null | grep -q ":${port} "; do
#        port=$((port + 1))
#    done
#    echo $port

uci_get_by_port() {
	local default_start_port=2001
	local min_port=1025
	local max_port=49151
	local port="$1"
	local protocol=$(echo "$2" | tr 'A-Z' 'a-z')
	local LOCK_FILE="${LOCK_PATH}/${CONFIG}_get_prot.lock"
	while ! mkdir "$LOCK_FILE" 2>/dev/null; do
		sleep 1
	done
	if [ "$port" = "auto" ]; then
		local now last_time diff last_port
		now=$(date +%s 2>/dev/null)
		last_time=$(get_cache_var "last_get_new_port_time")
		if [ -n "$now" ] && [ -n "$last_time" ]; then
			diff=$(expr "$now" - "$last_time")
			[ "$diff" -lt 0 ] && diff=$(expr 0 - "$diff")
		else
			diff=999
		fi
		if [ "$diff" -gt 10 ]; then
			port=$default_start_port
		else
			last_port=$(get_cache_var "last_get_new_port_auto")
			if [ -n "$last_port" ]; then
				port=$(expr "$last_port" + 1)
			else
				port=$default_start_port
			fi
		fi
	fi
	[ "$port" -lt $min_port -o "$port" -gt $max_port ] && port=$default_start_port
	local start_port="$port"
	while :; do
		if [ "$(check_port_exists "$port" "$protocol")" = 0 ]; then
			break
		fi
		port=$(expr "$port" + 1)
		if [ "$port" -gt $max_port ]; then
			port=$min_port
		fi
		[ "$port" = "$start_port" ] && {
			rmdir "$LOCK_FILE" 2>/dev/null
			return 1
		}
	done
	if [ "$1" = "auto" ]; then
		set_cache_var "last_get_new_port_auto" "$port"
		[ -n "$now" ] && set_cache_var "last_get_new_port_time" "$now"
	fi
	rmdir "$LOCK_FILE" 2>/dev/null
	echo "$port"
}

url_test_hy2() {
    local node_id=$1

    # 读取配置
    local server=$(uci_get_by_name ${node_id} server)
    local port=$(uci_get_by_name ${node_id} server_port)
    local auth=$(uci_get_by_name ${node_id} hy2_auth)
    local tls=$(uci_get_by_name ${node_id} tls)
    local insecure=$(uci_get_by_name ${node_id} insecure)
    local tls_host=$(uci_get_by_name ${node_id} tls_host)

    # 获取本地端口
	# local tmp_port=$(uci_get_by_port 48900 tcp,udp)
    local tmp_port=$(uci_get_by_port auto tcp,udp)

    # 生成Hysteria2配置文件
    local config_file="/tmp/hy2_test_${node_id}.yaml"
    cat > "$config_file" <<-EOF
		server: ${server}:${port}
		auth: "${auth}"
		tls:
		  insecure: true
	EOF

    # 如果 tls_host 非空，动态添加 sni 行
    [ -n "$tls_host" ] && echo "  sni: \"${tls_host}\"" >> "$config_file"

    # 追加 socks5 监听配置
    cat >> "$config_file" <<-EOF
		socks5:
		  listen: 127.0.0.1:${tmp_port}
	EOF

    # echo "Debug: 配置文件已生成: $config_file" >&2

    # 启动Hysteria2客户端
    hysteria client --disable-update-check -c "$config_file" >/dev/null 2>&1 &
    local pid=$!
    echo $pid > "/tmp/hy2_test_${node_id}.pid"

    # 等待端口启动
    sleep 1

    # 测试代理
    # local result=$(curl --connect-timeout 3 --max-time 3 -s -o /dev/null -I -w "%{http_code}:%{time_pretransfer}" --socks5 127.0.0.1:${tmp_port} "${probeUrl}" 2>/dev/null)
	local curlx="socks5h://127.0.0.1:${tmp_port}"
	local probeUrl=$(uci_get_by_type server_subscribe url_test_url https://www.google.com/generate_204)
	local result=$(curl --connect-timeout 3 --max-time 5 -o /dev/null -I -skL -w "%{http_code}:%{time_pretransfer}" -x ${curlx} "${probeUrl}" 2>/dev/null)

    # 清理
    # kill -9 $pid 2>/dev/null
	local pid_file="/tmp/hy2_test_${node_id}.pid"
	[ -s "$pid_file" ] && kill -9 "$(head -n 1 "$pid_file")" >/dev/null 2>&1
	pgrep -af "hysteria.*${config_file}" | awk '! /test\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
    rm -f "$config_file" "$pid_file"

    echo $result
}

case $1 in
	url_test_hy2)
		url_test_hy2 $2
		;;
esac