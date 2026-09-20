#!/bin/bash
# ---------- 最小日志 ----------
# ============================================================
# update_dashboard.sh
# SSR Plus+ 专用
# ============================================================

. /lib/functions.sh

# ---------- 最小日志 ----------
LOG_OUT() {
	local msg="$1"
	logger -t "shadowsocksr-dashboard" "$msg" 2>/dev/null
	echo "$msg"
}

LOG_WARN() {
	local msg="$1"
	logger -t "shadowsocksr-dashboard" "WARN: $msg" 2>/dev/null
	echo "WARN: $msg"
}

# ---------- ETag 缓存（来自 openclash_etag.sh） ----------
ETAG_CACHE="/etc/ssrplus/etag"

GET_ETAG_TIMESTAMP_BY_PATH() {
	local path=$1
	[ ! -f "$ETAG_CACHE" ] && return 1

	local path_hash=$(echo -n "$path" | md5sum | cut -d' ' -f1)

	awk -v hash="$path_hash" '
		$0 ~ "^\\[" hash "\\]" { found=1; next }
		/^\[/ { found=0 }
		found && /^time=/ { print $0; exit }
	' "$ETAG_CACHE" | cut -d'=' -f2- | sed 's/^"//;s/"$//'
}

GET_ETAG_BY_PATH() {
	local path=$1
	[ ! -f "$ETAG_CACHE" ] && return 1

	local path_hash=$(echo -n "$path" | md5sum | cut -d' ' -f1)

	awk -v hash="$path_hash" '
		$0 ~ "^\\[" hash "\\]" { found=1; next }
		/^\[/ { found=0 }
		found && /^etag=/ { print $0; exit }
	' "$ETAG_CACHE" | cut -d'=' -f2- | sed 's/^"//;s/"$//'
}

SAVE_ETAG_TO_CACHE() {
	local url="\"$1\""
	local etag="\"$2\""
	local path="\"$3\""
	local time="\"$(date '+%Y-%m-%d %H:%M:%S')\""
	local path_hash=$(echo -n "$3" | md5sum | cut -d' ' -f1)

	mkdir -p "$(dirname "$ETAG_CACHE")"

	[ ! -f "$ETAG_CACHE" ] && echo "# ETag Cache File" > "$ETAG_CACHE"

	if grep -q "^\[$path_hash\]" "$ETAG_CACHE"; then
		local temp_file="${ETAG_CACHE}.tmp"
		awk -v hash="$path_hash" \
			-v new_url="$url" \
			-v new_etag="$etag" \
			-v new_path="$path" \
			-v new_time="$time" '
			$0 ~ "^\\[" hash "\\]" {
				print;
				found=1;
				next
			}
			/^\[/ { found=0 }
			found && /^url=/ {
				print "url=" new_url;
				next
			}
			found && /^path=/ {
				print "path=" new_path;
				next
			}
			found && /^etag=/ {
				print "etag=" new_etag;
				next
			}
			found && /^time=/ {
				print "time=" new_time;
				next
			}
			{ print }
		' "$ETAG_CACHE" > "$temp_file" && mv "$temp_file" "$ETAG_CACHE"
	else
		cat >> "$ETAG_CACHE" << EOF

[$path_hash]
url=$url
path=$path
etag=$etag
time=$time
EOF
	fi
}

# ---------- 下载器（精简版 + ETag） ----------
DEFAULT_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

DOWNLOAD_FAILURE_OUTPUT() {
	local exit_code="$1"
	local http_code="$2"
	local output="$3"
	if [ -n "$output" ]; then
		printf '%s' "$output"
	elif [ -n "$http_code" ] && [ "$http_code" != "000" ]; then
		printf 'HTTP status %s' "$http_code"
	elif [ -n "$exit_code" ]; then
		printf 'curl exit code %s' "$exit_code"
	else
		printf 'unknown error'
	fi
}

# 精简版 + ETag：只下载 + ETag 304 判断，不 Checksum
DOWNLOAD_FILE_CURL() {
	[ -z "$1" ] || [ -z "$2" ] && return 1
	local DOWNLOAD_URL="$1"
	local DOWNLOAD_PATH="$2"
	local FILE_PATH="$3"
	local DOWNLOAD_UA="$4"
	[ -z "$DOWNLOAD_UA" ] && DOWNLOAD_UA="$DEFAULT_UA"

	local HEADER_TMP="/tmp/ssr_dashboard_header.$$"
	local DOWNLOAD_TMP="${DOWNLOAD_PATH}.download.$$"
	local HTTP_CODE
	local EXIR_CODE
	local CURL_OUTPUT
	local OUTPUT
	local CACHED_ETAG
	local ETAG_HEADER=""

    # ---- ETag 读取 ----
	CACHED_ETAG=$(GET_ETAG_BY_PATH "$FILE_PATH")
	if [ -n "$CACHED_ETAG" ] && [ -e "$FILE_PATH" ]; then
		local FILE_MTIME
		local LAST_UPDATE
		FILE_MTIME=$(date -r "$FILE_PATH" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
		LAST_UPDATE=$(GET_ETAG_TIMESTAMP_BY_PATH "$FILE_PATH")
		if [ -n "$LAST_UPDATE" ] && [ -n "$FILE_MTIME" ] && [ "$LAST_UPDATE" = "$FILE_MTIME" ]; then
			ETAG_HEADER="If-None-Match: \"${CACHED_ETAG}\""
		fi
	fi

	rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"

	local DOWNLOAD_TRY=0
	local MAX_DOWNLOAD_RETRIES=3
	while [ "$DOWNLOAD_TRY" -lt "$MAX_DOWNLOAD_RETRIES" ]; do
		DOWNLOAD_TRY=$((DOWNLOAD_TRY + 1))
		rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"

		if [ -n "$ETAG_HEADER" ]; then
			CURL_OUTPUT=$(curl -w "\n%{http_code}" -SsL \
				--connect-timeout 30 -m 180 \
				--speed-time 30 --speed-limit 1 \
				--retry 2 \
				-D "$HEADER_TMP" \
				-H "User-Agent: ${DOWNLOAD_UA}" \
				-H "$ETAG_HEADER" \
				"$DOWNLOAD_URL" -o "$DOWNLOAD_TMP" 2>&1)
		else
			CURL_OUTPUT=$(curl -w "\n%{http_code}" -SsL \
				--connect-timeout 30 -m 180 \
				--speed-time 30 --speed-limit 1 \
				--retry 2 \
				-D "$HEADER_TMP" \
				-H "User-Agent: ${DOWNLOAD_UA}" \
				"$DOWNLOAD_URL" -o "$DOWNLOAD_TMP" 2>&1)
		fi
		EXIR_CODE=$?
		HTTP_CODE=$(echo "$CURL_OUTPUT" | tail -n1)

		# 成功：200（有新内容）或 304（未修改）
		if { [ "$EXIR_CODE" -eq 0 ] && [ "$HTTP_CODE" = "200" ]; } || \
			{ [ "$EXIR_CODE" -eq 0 ] && [ "$HTTP_CODE" = "304" ] && [ -e "$FILE_PATH" ]; }; then
			break
		fi
		[ "$DOWNLOAD_TRY" -lt "$MAX_DOWNLOAD_RETRIES" ] && sleep 1
	done

	# ---- 304：文件未修改，直接用旧的 ----
	if [ "$EXIR_CODE" -eq 0 ] && [ "$HTTP_CODE" = "304" ] && [ -e "$FILE_PATH" ]; then
		rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"
		return 2
	fi

	# ---- 失败 ----
	if [ "$EXIR_CODE" -ne 0 ] || [ "$HTTP_CODE" != "200" ]; then
		OUTPUT=$(echo "$CURL_OUTPUT" | sed '$d' | grep -a 'curl:' | tail -n 1)
		OUTPUT=$(DOWNLOAD_FAILURE_OUTPUT "$EXIR_CODE" "$HTTP_CODE" "$OUTPUT")
		LOG_OUT "【${DOWNLOAD_PATH}】Download Failed:【${OUTPUT}】"
		rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"
		return 1
	fi

	# ---- 200：保存新文件 ----
	if ! mv -f "$DOWNLOAD_TMP" "$DOWNLOAD_PATH"; then
		LOG_OUT "【${DOWNLOAD_PATH}】Download Failed:【Unable to save download file】"
		rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"
		return 1
	fi

	# ---- ETag 写入 ----
	local NEW_ETAG
	NEW_ETAG=$(grep -i "^etag:" "$HEADER_TMP" 2>/dev/null | tail -1 | cut -d' ' -f2- | tr -d '\r\n' | sed 's/^"//;s/"$//')
	if [ -n "$NEW_ETAG" ] && [ "$HTTP_CODE" = "200" ]; then
		SAVE_ETAG_TO_CACHE "$DOWNLOAD_URL" "$NEW_ETAG" "$FILE_PATH"
	fi

	rm -f "$HEADER_TMP" "$DOWNLOAD_TMP"
	return 0
}

set_lock() {
	exec 871>"/tmp/lock/shadowsocksr_dashboard.lock" 2>/dev/null
	flock -x 871 2>/dev/null
}

del_lock() {
	flock -u 871 2>/dev/null
	rm -rf "/tmp/lock/shadowsocksr_dashboard.lock" 2>/dev/null
}

validate_dashboard_dir() {
	local dashboard_dir="$1"
	local index_file="${dashboard_dir%/}/index.html"
	local ref=""
	local asset=""
	local script_found=0

	[ -s "$index_file" ] || return 1

	while IFS= read -r ref; do
		[ -n "$ref" ] || continue
		ref="${ref%%#*}"
		ref="${ref%%\?*}"
		ref="${ref#./}"

		case "$ref" in
			""|http://*|https://*|//*|/*|data:*|mailto:*) continue ;;
		esac

		case "$ref" in
			*.js|*.css)
				asset="${dashboard_dir%/}/$ref"
				[ -s "$asset" ] || return 1
				[ "${ref##*.}" = "js" ] && script_found=1
			;;
		esac
	done <<-EOF
$(grep -oE "(src|href)[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" "$index_file" 2>/dev/null | sed "s/^[^=]*=[[:space:]]*['\"]//;s/['\"]$//")
EOF

	[ "$script_found" -eq 1 ]
}

cleanup_dashboard_tmp() {
	rm -rf "$DASH_FILE_DIR" "$DASH_FILE_TMP" "$NEW_FILE_DIR" "$OLD_FILE_DIR" >/dev/null 2>&1
}

restore_old_dashboard() {
	rm -rf "$TARGET_FILE_DIR" >/dev/null 2>&1
	[ -d "$OLD_FILE_DIR" ] && mv "$OLD_FILE_DIR" "$TARGET_FILE_DIR" >/dev/null 2>&1
}

log_unzip_error() {
	LOG_OUT "Control Panel【$DASH_NAME - $DASH_TYPE】Unzip Error!"
	cleanup_dashboard_tmp
	del_lock
	exit 2
}

# 主流程
set_lock

DASH_NAME="$1"
DASH_TYPE="$2"
DASH_FILE_DIR="/tmp/dash.zip"
DASH_FILE_TMP="/tmp/dash/"

# 建议：如果 uci_get_config 未在外部定义，可使用 uci 替代或加上防护
github_address_mod=$(uci_get_config "github_address_mod" 2>/dev/null || echo 0)

if [ "$DASH_NAME" == "Dashboard" ]; then
	UNPACK_FILE_DIR="/usr/share/shadowsocksr/ui/dashboard/"
	if [ "$DASH_TYPE" == "Official" ]; then
		DOWNLOAD_PATH="https://codeload.github.com/ayanamist/clash-dashboard/zip/refs/heads/gh-pages"
		FILE_PATH_INCLUDE="clash-dashboard-gh-pages"
	else
		DOWNLOAD_PATH="https://codeload.github.com/MetaCubeX/Razord-meta/zip/refs/heads/gh-pages"
		FILE_PATH_INCLUDE="Razord-meta-gh-pages"
	fi
elif [ "$DASH_NAME" == "Yacd" ]; then
	UNPACK_FILE_DIR="/usr/share/shadowsocksr/ui/yacd/"
    if [ "$DASH_TYPE" == "Official" ]; then
		DOWNLOAD_PATH="https://codeload.github.com/haishanh/yacd/zip/refs/heads/gh-pages"
		FILE_PATH_INCLUDE="yacd-gh-pages"
	else
		DOWNLOAD_PATH="https://codeload.github.com/MetaCubeX/Yacd-meta/zip/refs/heads/gh-pages"
		FILE_PATH_INCLUDE="Yacd-meta-gh-pages"
	fi
elif [ "$DASH_NAME" == "Zashboard" ]; then
	UNPACK_FILE_DIR="/usr/share/shadowsocksr/ui/zashboard/"
	DOWNLOAD_PATH="https://codeload.github.com/Zephyruso/zashboard/zip/refs/heads/gh-pages-cdn-fonts"
	FILE_PATH_INCLUDE="zashboard-gh-pages-cdn-fonts"
else
	UNPACK_FILE_DIR="/usr/share/shadowsocksr/ui/metacubexd/"
	DOWNLOAD_PATH="https://codeload.github.com/MetaCubeX/metacubexd/zip/refs/heads/gh-pages"
	FILE_PATH_INCLUDE="metacubexd-gh-pages"
fi

TARGET_FILE_DIR="${UNPACK_FILE_DIR%/}"
TARGET_PARENT_DIR="$(dirname "$TARGET_FILE_DIR")"
NEW_FILE_DIR="${TARGET_PARENT_DIR}/.shadowsocksr_dashboard_new.$$"
OLD_FILE_DIR="${TARGET_PARENT_DIR}/.shadowsocksr_dashboard_old.$$"

DOWNLOAD_FILE_CURL "$DOWNLOAD_PATH" "$DASH_FILE_DIR" "$UNPACK_FILE_DIR"
DOWNLOAD_RESULT=$?

if [ "$DOWNLOAD_RESULT" -eq 0 ] && [ -s "$DASH_FILE_DIR" ]; then
	unzip -qt "$DASH_FILE_DIR" >/dev/null 2>&1
	if [ "$?" -eq "0" ]; then
		rm -rf "$DASH_FILE_TMP" "$NEW_FILE_DIR" "$OLD_FILE_DIR" >/dev/null 2>&1
		unzip -q "$DASH_FILE_DIR" -d "$DASH_FILE_TMP" >/dev/null 2>&1
		if [ "$?" -eq "0" ] && [ -d "$DASH_FILE_TMP$FILE_PATH_INCLUDE" ]; then
			mkdir -p "$NEW_FILE_DIR" >/dev/null 2>&1 || log_unzip_error
			cp -rf "$DASH_FILE_TMP$FILE_PATH_INCLUDE"/. "$NEW_FILE_DIR" >/dev/null 2>&1 || log_unzip_error
			validate_dashboard_dir "$NEW_FILE_DIR" || log_unzip_error

			mkdir -p "$TARGET_PARENT_DIR" >/dev/null 2>&1 || log_unzip_error
			if [ -d "$TARGET_FILE_DIR" ]; then
				mv "$TARGET_FILE_DIR" "$OLD_FILE_DIR" >/dev/null 2>&1 || log_unzip_error
			fi
            if mv "$NEW_FILE_DIR" "$TARGET_FILE_DIR" >/dev/null 2>&1 && validate_dashboard_dir "$TARGET_FILE_DIR"; then
				cleanup_dashboard_tmp
				LOG_OUT "Control Panel【$DASH_NAME - $DASH_TYPE】Download Successful!"
				del_lock
				exit 0
			else
				restore_old_dashboard
				log_unzip_error
			fi
		else
			log_unzip_error
		fi
	else
		log_unzip_error
	fi
elif [ "$DOWNLOAD_RESULT" -eq 2 ]; then
	if validate_dashboard_dir "$UNPACK_FILE_DIR"; then
		cleanup_dashboard_tmp
		LOG_OUT "Control Panel【$DASH_NAME - $DASH_TYPE】Download Successful!"
		del_lock
		exit 0
	else
		log_unzip_error
	fi
else
	cleanup_dashboard_tmp
	LOG_OUT "Control Panel【$DASH_NAME - $DASH_TYPE】Download Error!"
	del_lock
	exit 1
fi

del_lock
