#!/bin/sh

set -u

XRAY_RELEASE_PAGE="https://github.com/fw876/helloworld/releases/latest"
XRAY_BINARY="/usr/bin/xray"

# Geo 数据文件 URL
GEOIP_REPO="Loyalsoldier/geoip"
GEOSITE_REPO="Loyalsoldier/v2ray-rules-dat"
COUNTRY_MMDB_REPO="alecthw/mmdb_china_ip_list"

# Geo 数据文件路径
COUNTRY_MMDB_FILE="/usr/share/shadowsocksr/Country.mmdb"
GEOIP_DAT_FILE="/usr/share/v2ray/geoip.dat"
GEOSITE_DAT_FILE="/usr/share/v2ray/geosite.dat"
OPENCLASH_GEOSITE_FILE="/etc/openclash/GeoSite.dat"

# geo 版本存储
GEO_VERSION_FILE="/tmp/ssrplus-geo/geo_versions.json"

log_kv() {
	key="$1"
	shift
	printf '%s=%s\n' "$key" "$*"
}

file_mtime() {
	local path="$1"
	[ -f "$path" ] || {
		printf '%s' ''
		return 0
	}
	date -r "$path" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf '%s' ''
}

trim_version() {
	printf '%s' "$1" | sed 's/^v//'
}

get_component_mirror() {
	if [ -n "${COMPONENT_MIRROR:-}" ]; then
		echo "$COMPONENT_MIRROR"
		return 0
	fi
	uci -q get shadowsocksr.@global[0].component_mirror 2>/dev/null || echo "direct"
}

mirror_wrap_url() {
	local raw_url="$1"
	local mirror

	mirror="$(get_component_mirror)"
	case "$mirror" in
		direct|"")
			printf '%s' "$raw_url"
			;;
		ghproxy)
			printf 'https://mirror.ghproxy.com/%s' "$raw_url"
			;;
		ghproxy_cc)
			printf 'https://ghproxy.cc/%s' "$raw_url"
			;;
		ghfast)
			printf 'https://ghfast.top/%s' "$raw_url"
			;;
		jsdelivr)
			case "$raw_url" in
				https://github.com/MetaCubeX/mihomo/releases/download/*)
					printf '%s' "$raw_url" | sed 's#https://github.com/MetaCubeX/mihomo/releases/download/\(v[^/]*\)/\(.*\)#https://fastly.jsdelivr.net/gh/MetaCubeX/mihomo@\1/\2#'
					;;
				https://github.com/Loyalsoldier/geoip/releases/download/*)
					printf '%s' "$raw_url" | sed 's#https://github.com/Loyalsoldier/geoip/releases/download/\([^/]*\)/\(.*\)#https://testingcf.jsdelivr.net/gh/Loyalsoldier/geoip@release/\2#'
					;;
				https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/*)
					printf '%s' "$raw_url" | sed 's#https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/\([^/]*\)/\(.*\)#https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/\2#'
					;;
				https://github.com/alecthw/mmdb_china_ip_list/releases/download/*)
					printf '%s' "$raw_url" | sed 's#https://github.com/alecthw/mmdb_china_ip_list/releases/download/\([^/]*\)/\(.*\)#https://testingcf.jsdelivr.net/gh/alecthw/mmdb_china_ip_list@release/lite/\2#' | sed 's#-lite##'
					;;
				*)
					printf '%s' "$raw_url"
					;;
			esac
			;;
		*)
			printf '%s' "$raw_url"
			;;
	esac
}

version_gt() {
	local left right first

	left="$(trim_version "${1:-}")"
	right="$(trim_version "${2:-}")"

	[ -n "$left" ] || return 1
	[ -n "$right" ] || return 1
	[ "$left" = "$right" ] && return 1

	first="$(printf '%s\n%s\n' "$left" "$right" | sort -V | tail -n 1)"
	[ "$first" = "$left" ]
}

naiveproxy_versions_equal() {
	local left right

	left="$(trim_version "${1:-}")"
	right="$(trim_version "${2:-}")"
	[ -n "$left" ] || return 1
	[ -n "$right" ] || return 1
	[ "$left" = "$right" ] && return 0
	[ "${left%%-*}" = "${right%%-*}" ]
}

get_openwrt_arch() {
	local arch

	arch=""
	if [ -r /etc/openwrt_release ]; then
		arch="$(. /etc/openwrt_release 2>/dev/null; printf '%s' "${DISTRIB_ARCH:-}")"
	fi

	if [ -z "$arch" ] && command -v opkg >/dev/null 2>&1; then
		arch="$(opkg print-architecture 2>/dev/null | awk '$2 != "all" && $2 != "noarch" { print $2 }' | tail -n 1)"
	fi

	if [ -z "$arch" ] && command -v uname >/dev/null 2>&1; then
		arch="$(uname -m 2>/dev/null)"
	fi

	printf '%s' "$arch"
}

detect_package_manager() {
	if command -v apk >/dev/null 2>&1; then
		printf '%s' 'apk'
		return 0
	fi

	if command -v opkg >/dev/null 2>&1; then
		printf '%s' 'opkg'
		return 0
	fi

	return 1
}

find_mihomo_binary() {
	if command -v mihomo >/dev/null 2>&1; then
		command -v mihomo
		return 0
	fi

	for path in /usr/bin/mihomo /usr/libexec/mihomo /etc/ssrplus/bin/mihomo; do
		if [ -x "$path" ]; then
			printf '%s' "$path"
			return 0
		fi
	done

	return 1
}

find_naiveproxy_binary() {
	if command -v naive >/dev/null 2>&1; then
		command -v naive
		return 0
	fi

	for path in /usr/bin/naive /usr/libexec/naive /etc/ssrplus/bin/naive; do
		if [ -x "$path" ]; then
			printf '%s' "$path"
			return 0
		fi
	done

	return 1
}

get_xray_current_version() {
	if [ ! -x "$XRAY_BINARY" ]; then
		return 1
	fi

	"$XRAY_BINARY" version 2>/dev/null | sed -n 's/^Xray[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' | sed -n '1p'
	return 0
}

get_mihomo_current_version() {
	local pm version binary

	pm="$(detect_package_manager 2>/dev/null || true)"
	case "$pm" in
		apk)
			version="$(apk list -I mihomo 2>/dev/null | sed -n 's/^mihomo-\([^[:space:]]*\).*$/\1/p' | sed -n '1p')"
			;;
		opkg)
			version="$(opkg status mihomo 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p' | sed -n '1p')"
			;;
	esac

	if [ -n "${version:-}" ]; then
		printf '%s' "$version"
		return 0
	fi

	binary="$(find_mihomo_binary)" || return 1
	"$binary" -v 2>/dev/null | sed -n 's/.* v\([0-9][0-9.]*\).*/\1/p' | sed -n '1p'
	return 0
}

get_naiveproxy_current_version() {
	local pm version binary

	pm="$(detect_package_manager 2>/dev/null || true)"
	case "$pm" in
		apk)
			version="$(apk list -I naiveproxy 2>/dev/null | sed -n 's/^naiveproxy-\([^[:space:]]*\).*$/\1/p' | sed -n '1p')"
			;;
		opkg)
			version="$(opkg status naiveproxy 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p' | sed -n '1p')"
			;;
	esac

	if [ -n "${version:-}" ]; then
		printf '%s' "$version"
		return 0
	fi

	binary="$(find_naiveproxy_binary)" || return 1
	"$binary" --version 2>&1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?' | sed -n '1p'
	return 0
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1
}

select_wget_cmd() {
	if require_cmd wget-ssl; then
		printf '%s' 'wget-ssl'
		return 0
	fi

	if require_cmd wget; then
		printf '%s' 'wget'
		return 0
	fi

	return 1
}

curl_effective_url() {
	local target="$1"
	local effective=""
	local headers=""
	local location=""

	headers="$(curl -kfsSI --http1.1 --connect-timeout 10 --retry 2 -A 'curl/8.0' -H 'Accept-Encoding: identity' "$target" 2>/dev/null || true)"
	location="$(printf '%s\n' "$headers" | sed -n 's/^[Ll]ocation:[[:space:]]*//p' | sed 's/\r$//' | sed 's/[[:space:]]\+\[following\]$//' | sed -n '1p')"
	[ -n "$location" ] && effective="$location"
	[ -n "$effective" ] || effective="$(curl -kfsSL --http1.1 --connect-timeout 10 --retry 2 -A 'curl/8.0' -H 'Accept-Encoding: identity' -o /dev/null -w '%{url_effective}' "$target" 2>/dev/null || true)"
	[ -n "$effective" ] || return 1

	printf '%s' "$effective"
}

wget_effective_url() {
	local target="$1"
	local wget_cmd output location

	wget_cmd="$(select_wget_cmd)" || return 1
	output="$($wget_cmd --server-response --max-redirect=0 --spider --timeout=20 --tries=3 --no-check-certificate "$target" 2>&1 || true)"
	location="$(printf '%s\n' "$output" | sed -n 's/^[Ll]ocation:[[:space:]]*//p' | sed 's/\r$//' | sed 's/[[:space:]]\+\[following\]$//' | sed -n '1p')"

	if [ -n "$location" ]; then
		printf '%s' "$location"
		return 0
	fi

	printf '%s\n' "$output" | grep -qE 'HTTP/[0-9.]+ 200' || return 1
	printf '%s' "$target"
}

effective_url() {
	local target="$1"
	local url=""

	url="$(curl_effective_url "$target" 2>/dev/null || true)"
	[ -n "$url" ] || url="$(wget_effective_url "$target" 2>/dev/null || true)"
	[ -n "$url" ] || return 1
	printf '%s' "$url"
}

fetch_text() {
	local url="$1"
	local wget_cmd

	if curl -kfsSL --http1.1 --connect-timeout 10 --retry 2 -A 'curl/8.0' -H 'Accept: application/vnd.github+json' "$url" 2>/dev/null; then
		return 0
	fi

	wget_cmd="$(select_wget_cmd)" || return 1
	"$wget_cmd" --header='Accept: application/vnd.github+json' --timeout=20 --tries=3 --no-check-certificate -O - "$url" 2>/dev/null
}

download_file() {
	local url="$1"
	local output="$2"
	local wget_cmd

	if curl -kfsSL --http1.1 --connect-timeout 10 --retry 2 -A 'curl/8.0' -H 'Accept-Encoding: identity' -o "$output" "$url" 2>/dev/null; then
		return 0
	fi

	wget_cmd="$(select_wget_cmd)" || return 1
	"$wget_cmd" --no-check-certificate --timeout=20 --tries=3 -O "$output" "$url" >/dev/null 2>&1
}

store_geo_version() {
	local geo="$1"
	local version="$2"
	
	mkdir -p "$(dirname "$GEO_VERSION_FILE")"
	
	if [ -f "$GEO_VERSION_FILE" ]; then
		if grep -q "\"$geo\":" "$GEO_VERSION_FILE" 2>/dev/null; then
			sed -i "s/\"$geo\":\"[^\"]*\"/\"$geo\":\"$version\"/" "$GEO_VERSION_FILE"
		else
			sed -i "s/}$/,\"$geo\":\"$version\"}/" "$GEO_VERSION_FILE"
		fi
	else
		echo "{\"$geo\":\"$version\"}" > "$GEO_VERSION_FILE"
	fi
}

get_stored_geo_version() {
	local geo="$1"
	local version=""
	
	if [ -f "$GEO_VERSION_FILE" ]; then
		version="$(cat "$GEO_VERSION_FILE" 2>/dev/null | grep -o "\"$geo\":\"[^\"]*\"" | cut -d'"' -f4)"
	fi
	printf '%s' "$version"
}

get_geo_current_version() {
	local geo="$1"
	local file_path="$2"
	local stored_version=""
	local file_version=""
	
	stored_version="$(get_stored_geo_version "$geo")"
	if [ -n "$stored_version" ]; then
		printf '%s' "$stored_version"
		return 0
	fi
	
	if [ -f "$file_path" ]; then
		file_version="$(file_mtime "$file_path")"
		if [ -n "$file_version" ]; then
			store_geo_version "$geo" "$file_version"
		fi
		printf '%s' "$file_version"
		return 0
	fi
	
	return 1
}

get_geo_latest_tag() {
	local repo="$1"
	local location tag

	location="$(effective_url "https://github.com/$repo/releases/latest" 2>/dev/null)" || return 1
	tag="$(printf '%s' "$location" | sed -n 's#.*/tag/\([0-9][^/]*\)$#\1#p' | sed -n '1p')"
	[ -n "$tag" ] || return 1
	printf '%s' "$tag"
}

get_geo_latest_info() {
	local repo="$1"
	local asset="$2"
	local tag version url
	
	tag="$(get_geo_latest_tag "$repo")" || return 3
	version="$(trim_version "$tag")"
	url="$(mirror_wrap_url "https://github.com/$repo/releases/download/$tag/$asset")"
	
	[ -n "$tag" ] && [ -n "$version" ] && [ -n "$url" ] || return 4
	
	log_kv latest_version "$version"
	log_kv download_url "$url"
	return 0
}

get_country_mmdb_current_version() {
	get_geo_current_version "country_mmdb" "$COUNTRY_MMDB_FILE"
}

get_geosite_current_version() {
	get_geo_current_version "GeoSite" "$OPENCLASH_GEOSITE_FILE"
}

get_v2ray_geoip_current_version() {
	get_geo_current_version "v2ray_geoip" "$GEOIP_DAT_FILE"
}

get_v2ray_geosite_current_version() {
	get_geo_current_version "v2ray_geosite" "$GEOSITE_DAT_FILE"
}

country_mmdb_info() {
	local current installed latest_output latest_rc latest_version can_upgrade

	installed=0
	current=""
	
	if current="$(get_country_mmdb_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_geo_latest_info "$COUNTRY_MMDB_REPO" "Country-lite.mmdb" 2>/dev/null)"
	latest_rc=$?

	log_kv component country_mmdb
	log_kv installed "$installed"
	log_kv current_version "$current"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

geosite_info() {
	local current installed latest_output latest_rc latest_version can_upgrade

	installed=0
	current=""
	
	if current="$(get_geosite_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_geo_latest_info "$GEOSITE_REPO" "geosite.dat" 2>/dev/null)"
	latest_rc=$?

	log_kv component geosite
	log_kv installed "$installed"
	log_kv current_version "$current"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

v2ray_geoip_info() {
	local current installed latest_output latest_rc latest_version can_upgrade

	installed=0
	current=""
	
	if current="$(get_v2ray_geoip_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_geo_latest_info "$GEOIP_REPO" "geoip-only-cn-private.dat" 2>/dev/null)"
	latest_rc=$?

	log_kv component v2ray_geoip
	log_kv installed "$installed"
	log_kv current_version "$current"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

v2ray_geosite_info() {
	local current installed latest_output latest_rc latest_version can_upgrade

	installed=0
	current=""
	
	if current="$(get_v2ray_geosite_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_geo_latest_info "$GEOSITE_REPO" "geosite.dat" 2>/dev/null)"
	latest_rc=$?

	log_kv component v2ray_geosite
	log_kv installed "$installed"
	log_kv current_version "$current"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

country_mmdb_local_info() {
	local current installed

	installed=0
	current=""
	
	if current="$(get_country_mmdb_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component country_mmdb
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv can_upgrade 0
	log_kv error ''
}

geosite_local_info() {
	local current installed

	installed=0
	current=""

	if current="$(get_geosite_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component geosite
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv can_upgrade 0
	log_kv error ''
}

v2ray_geoip_local_info() {
	local current installed

	installed=0
	current=""
	
	if current="$(get_v2ray_geoip_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component v2ray_geoip
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv can_upgrade 0
	log_kv error ''
}

v2ray_geosite_local_info() {
	local current installed

	installed=0
	current=""
	
	if current="$(get_v2ray_geosite_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component v2ray_geosite
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv can_upgrade 0
	log_kv error ''
}

country_mmdb_upgrade() {
	local latest_output latest_rc latest_version download_url tmp_dir backup_file current_before current_after

	latest_output="$(get_geo_latest_info "$COUNTRY_MMDB_REPO" "Country-lite.mmdb" 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	current_before="$(get_country_mmdb_current_version 2>/dev/null || true)"
	
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi

	tmp_dir="$(mktemp -d /tmp/ssrplus-countrymmdb.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	backup_file="$tmp_dir/countrymmdb.backup"

	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$tmp_dir/Country.mmdb"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$tmp_dir/Country.mmdb" ]; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi
	
	if [ -f "$COUNTRY_MMDB_FILE" ]; then
		cp -fp "$COUNTRY_MMDB_FILE" "$backup_file" 2>/dev/null || true
	fi

	if ! cp -f "$tmp_dir/Country.mmdb" "$COUNTRY_MMDB_FILE"; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$COUNTRY_MMDB_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	store_geo_version "country_mmdb" "$latest_version"

	current_after="$(get_country_mmdb_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$COUNTRY_MMDB_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Installed file failed to verify'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv message 'Upgrade completed'
	return 0
}

geosite_upgrade() {
	local latest_output latest_rc latest_version download_url tmp_dir backup_file current_before current_after

	latest_output="$(get_geo_latest_info "$GEOSITE_REPO" "geosite.dat" 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	current_before="$(get_geosite_current_version 2>/dev/null || true)"
	
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi
	
	tmp_dir="$(mktemp -d /tmp/ssrplus-GeoSite.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	backup_file="$tmp_dir/GeoSite.backup"

	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$tmp_dir/GeoSite.dat"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$tmp_dir/GeoSite.dat" ]; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi
	
	if [ -f "$OPENCLASH_GEOSITE_FILE" ]; then
		cp -fp "$OPENCLASH_GEOSITE_FILE" "$backup_file" 2>/dev/null || true
	fi

	if ! cp -f "$tmp_dir/GeoSite.dat" "$OPENCLASH_GEOSITE_FILE"; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$OPENCLASH_GEOSITE_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	store_geo_version "GeoSite" "$latest_version"

	current_after="$(get_geosite_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$OPENCLASH_GEOSITE_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Installed file failed to verify'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv message 'Upgrade completed'
	return 0
}

v2ray_geoip_upgrade() {
	local latest_output latest_rc latest_version download_url tmp_dir backup_file current_before current_after

	latest_output="$(get_geo_latest_info "$GEOIP_REPO" "geoip-only-cn-private.dat" 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	current_before="$(get_v2ray_geoip_current_version 2>/dev/null || true)"
	
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi
	
	tmp_dir="$(mktemp -d /tmp/ssrplus-v2raygeoip.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	backup_file="$tmp_dir/v2raygeoip.backup"

	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$tmp_dir/geoip.dat"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$tmp_dir/geoip.dat" ]; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi
	
	if [ -f "$GEOIP_DAT_FILE" ]; then
		cp -fp "$GEOIP_DAT_FILE" "$backup_file" 2>/dev/null || true
	fi

	if ! cp -f "$tmp_dir/geoip.dat" "$GEOIP_DAT_FILE"; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$GEOIP_DAT_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	store_geo_version "v2ray_geoip" "$latest_version"

	current_after="$(get_v2ray_geoip_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$GEOIP_DAT_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Installed file failed to verify'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv message 'Upgrade completed'
	return 0
}

v2ray_geosite_upgrade() {
	local latest_output latest_rc latest_version download_url tmp_dir backup_file current_before current_after

	latest_output="$(get_geo_latest_info "$GEOSITE_REPO" "geosite.dat" 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	current_before="$(get_v2ray_geosite_current_version 2>/dev/null || true)"
	
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi
	
	tmp_dir="$(mktemp -d /tmp/ssrplus-v2raygeosite.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	backup_file="$tmp_dir/v2raygeosite.backup"

	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$tmp_dir/geosite.dat"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$tmp_dir/geosite.dat" ]; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi
	
	if [ -f "$GEOSITE_DAT_FILE" ]; then
		cp -fp "$GEOSITE_DAT_FILE" "$backup_file" 2>/dev/null || true
	fi

	if ! cp -f "$tmp_dir/geosite.dat" "$GEOSITE_DAT_FILE"; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$GEOSITE_DAT_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	store_geo_version "v2ray_geosite" "$latest_version"

	current_after="$(get_v2ray_geosite_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		if [ -f "$backup_file" ]; then
			cp -fp "$backup_file" "$GEOSITE_DAT_FILE" 2>/dev/null || true
		fi
		log_kv success 0
		log_kv message 'Installed file failed to verify'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv message 'Upgrade completed'
	return 0
}

get_helloworld_latest_tag() {
	local location tag

	location="$(effective_url "$XRAY_RELEASE_PAGE")" || return 1
	tag="$(printf '%s' "$location" | sed -n 's#.*/tag/\([^/]*\)$#\1#p' | sed -n '1p')"
	[ -n "$tag" ] || return 1
	printf '%s' "$tag"
}

select_xray_asset() {
	local asset_list="$1"
	local pm="$2"
	local arch="$3"
	local candidate

	case "$pm" in
		apk)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^xray-core-[^[:space:]]+\.apk$' | grep -F "_${arch}.apk" | sed -n '1p')"
			;;
		opkg)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^xray-core_[^[:space:]]+\.ipk$' | grep -F "_${arch}.ipk" | sed -n '1p')"
			;;
		*)
			return 1
			;;
	esac

	[ -n "$candidate" ] || return 1
	printf '%s' "$candidate"
}

xray_asset_version() {
	local asset="$1"
	local arch="$2"
	local version

	case "$asset" in
		xray-core_*_"$arch".ipk)
			version="${asset#xray-core_}"
			version="${version%_${arch}.ipk}"
			;;
		xray-core-*_"$arch".apk)
			version="${asset#xray-core-}"
			version="${version%_${arch}.apk}"
			;;
		*)
			return 1
			;;
	esac

	version="$(printf '%s' "$version" | sed 's/-r[0-9][0-9]*$//')"
	[ -n "$version" ] || return 1
	printf '%s' "$version"
}

get_xray_latest_info() {
	local pm tag version asset asset_list release_html url arch

	pm="$(detect_package_manager)" || return 2
	arch="$(get_openwrt_arch)"
	tag="$(get_helloworld_latest_tag)" || return 3
	release_html="$(fetch_text "https://github.com/fw876/helloworld/releases/expanded_assets/$tag")" || return 3
	asset_list="$(printf '%s\n' "$release_html" | sed -n 's#.*href="/fw876/helloworld/releases/download/[^/]*/\([^"]*\)".*#\1#p')"
	asset="$(select_xray_asset "$asset_list" "$pm" "$arch")" || return 4
	version="$(xray_asset_version "$asset" "$arch")" || return 4
	url="$(mirror_wrap_url "https://github.com/fw876/helloworld/releases/download/$tag/$asset")"

	[ -n "$tag" ] && [ -n "$version" ] && [ -n "$url" ] || return 4

	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset "$asset"
	log_kv latest_version "$version"
	log_kv download_url "$url"
	return 0
}

select_mihomo_asset() {
	local asset_list="$1"
	local pm="$2"
	local arch="$3"
	local candidate

	case "$pm" in
		apk)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^mihomo-[^[:space:]]+\.apk$' | grep -F "_${arch}.apk" | sed -n '1p')"
			;;
		opkg)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^mihomo_[^[:space:]]+\.ipk$' | grep -F "_${arch}.ipk" | sed -n '1p')"
			;;
		*)
			return 1
			;;
	esac

	[ -n "$candidate" ] || return 1
	printf '%s' "$candidate"
}

mihomo_asset_version() {
	local asset="$1"
	local arch="$2"
	local version

	case "$asset" in
		mihomo_*_"$arch".ipk)
			version="${asset#mihomo_}"
			version="${version%_${arch}.ipk}"
			;;
		mihomo-*_"$arch".apk)
			version="${asset#mihomo-}"
			version="${version%_${arch}.apk}"
			;;
		*)
			return 1
			;;
	esac

	[ -n "$version" ] || return 1
	printf '%s' "$version"
}

get_mihomo_latest_info() {
	local pm arch tag version asset asset_list release_html url

	pm="$(detect_package_manager)" || return 2
	arch="$(get_openwrt_arch)"
	tag="$(get_helloworld_latest_tag)" || return 3
	release_html="$(fetch_text "https://github.com/fw876/helloworld/releases/expanded_assets/$tag")" || return 3
	asset_list="$(printf '%s\n' "$release_html" | sed -n 's#.*href="/fw876/helloworld/releases/download/[^/]*/\([^"]*\)".*#\1#p')"
	asset="$(select_mihomo_asset "$asset_list" "$pm" "$arch")" || return 4
	version="$(mihomo_asset_version "$asset" "$arch")" || return 4
	url="$(mirror_wrap_url "https://github.com/fw876/helloworld/releases/download/$tag/$asset")"

	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset "$asset"
	log_kv latest_version "$version"
	log_kv download_url "$url"
	return 0
}

select_naiveproxy_asset() {
	local asset_list="$1"
	local pm="$2"
	local arch="$3"
	local candidate

	case "$pm" in
		apk)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^naiveproxy-[^[:space:]]+\.apk$' | grep -F "_${arch}.apk" | sed -n '1p')"
			;;
		opkg)
			candidate="$(printf '%s\n' "$asset_list" | grep -E '^naiveproxy_[^[:space:]]+\.ipk$' | grep -F "_${arch}.ipk" | sed -n '1p')"
			;;
		*)
			return 1
			;;
	esac

	[ -n "$candidate" ] || return 1
	printf '%s' "$candidate"
}

naiveproxy_asset_version() {
	local asset="$1"
	local arch="$2"
	local version

	case "$asset" in
		naiveproxy_*_"$arch".ipk)
			version="${asset#naiveproxy_}"
			version="${version%_${arch}.ipk}"
			;;
		naiveproxy-*_"$arch".apk)
			version="${asset#naiveproxy-}"
			version="${version%_${arch}.apk}"
			;;
		*)
			return 1
			;;
	esac

	[ -n "$version" ] || return 1
	printf '%s' "$version"
}

get_naiveproxy_latest_info() {
	local pm arch tag version asset asset_list release_html url

	pm="$(detect_package_manager)" || return 2
	arch="$(get_openwrt_arch)"
	tag="$(get_helloworld_latest_tag)" || return 3
	release_html="$(fetch_text "https://github.com/fw876/helloworld/releases/expanded_assets/$tag")" || return 3
	asset_list="$(printf '%s\n' "$release_html" | sed -n 's#.*href="/fw876/helloworld/releases/download/[^/]*/\([^"]*\)".*#\1#p')"
	asset="$(select_naiveproxy_asset "$asset_list" "$pm" "$arch")" || return 4
	version="$(naiveproxy_asset_version "$asset" "$arch")" || return 4
	url="$(mirror_wrap_url "https://github.com/fw876/helloworld/releases/download/$tag/$asset")"

	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset "$asset"
	log_kv latest_version "$version"
	log_kv download_url "$url"
	return 0
}

get_mainprogram_current_version() {
	local pm="$1"
	local version

	case "$pm" in
		apk)
			version="$(apk info -e luci-app-ssr-plus 2>/dev/null | sed -n 's/^luci-app-ssr-plus-\([0-9][^-[:space:]]*-[^[:space:]]*\).*$/\1/p' | sed -n '1p')"
			[ -n "$version" ] || version="$(apk list -I luci-app-ssr-plus 2>/dev/null | sed -n 's/^luci-app-ssr-plus-\([0-9][^-[:space:]]*-[^[:space:]]*\).*$/\1/p' | sed -n '1p')"
			;;
		opkg)
			version="$(opkg status luci-app-ssr-plus 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p' | sed -n '1p')"
			;;
	esac

	[ -n "$version" ] || return 1
	printf '%s' "$version"
}

mainprogram_asset_suffix() {
	case "$1" in
		apk)
			printf '%s' '.apk'
			;;
		opkg)
			printf '%s' '.ipk'
			;;
		*)
			return 1
			;;
	esac
}

select_mainprogram_asset() {
	local asset_list="$1"
	local pm="$2"
	local suffix candidate

	suffix="$(mainprogram_asset_suffix "$pm")" || return 1
	candidate="$(printf '%s\n' "$asset_list" | grep -F "$suffix" | grep -E '^luci-app-ssr-plus[_-]' | sed -n '1p')"
	[ -n "$candidate" ] || return 1
	printf '%s' "$candidate"
}

mainprogram_asset_version() {
	local asset="$1"
	local version

	version="$(printf '%s' "$asset" | sed -n 's/^luci-app-ssr-plus_\([^_]*\)_.*\.ipk$/\1/p')"
	[ -n "$version" ] || version="$(printf '%s' "$asset" | sed -n 's/^luci-app-ssr-plus-\(.*\)\.apk$/\1/p')"
	[ -n "$version" ] || return 1
	printf '%s' "$version"
}

get_mainprogram_latest_info() {
	local pm release_html tag version asset asset_list url

	pm="$(detect_package_manager)" || return 2
	tag="$(get_helloworld_latest_tag)" || return 3
	release_html="$(fetch_text "https://github.com/fw876/helloworld/releases/expanded_assets/$tag")" || return 3
	asset_list="$(printf '%s\n' "$release_html" | sed -n 's#.*href="/fw876/helloworld/releases/download/[^/]*/\([^"]*\)".*#\1#p')"
	asset="$(select_mainprogram_asset "$asset_list" "$pm")" || return 4
	version="$(mainprogram_asset_version "$asset" 2>/dev/null || trim_version "$tag")"
	url="$(mirror_wrap_url "https://github.com/fw876/helloworld/releases/download/$tag/$asset")"

	log_kv package_manager "$pm"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset "$asset"
	log_kv latest_version "$version"
	log_kv download_url "$url"
	return 0
}

mainprogram_info() {
	local pm current installed latest_output latest_rc latest_version arch asset can_upgrade

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	if [ -n "$pm" ] && current="$(get_mainprogram_current_version "$pm")" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_mainprogram_latest_info 2>/dev/null)"
	latest_rc=$?

	log_kv component mainprogram
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset ''

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			2) log_kv error 'unsupported_package_manager' ;;
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	pm="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	arch="$(printf '%s\n' "$latest_output" | sed -n 's/^arch=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

mainprogram_local_info() {
	local pm current installed

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	if [ -n "$pm" ] && current="$(get_mainprogram_current_version "$pm")" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component mainprogram
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv package_manager "$pm"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset ''
	log_kv can_upgrade 0
	log_kv error ''
}

mainprogram_install_package() {
	local pm="$1"
	local package_file="$2"

	case "$pm" in
		apk)
			apk add --allow-untrusted "$package_file" >/dev/null 2>&1
			;;
		opkg)
			opkg install "$package_file" >/dev/null 2>&1
			;;
		*)
			return 1
			;;
	esac
}

mainprogram_upgrade() {
	local latest_output latest_rc latest_version download_url package_manager asset tmp_dir package_file current_before current_after

	latest_output="$(get_mainprogram_latest_info 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			2) log_kv message 'Unsupported package manager' ;;
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	package_manager="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	current_before="$(get_mainprogram_current_version "$package_manager" 2>/dev/null || true)"

	tmp_dir="$(mktemp -d /tmp/ssrplus-mainprogram.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	package_file="$tmp_dir/$asset"
	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$package_file"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$package_file" ]; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if ! mainprogram_install_package "$package_manager" "$package_file"; then
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	current_after="$(get_mainprogram_current_version "$package_manager" 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		log_kv success 0
		log_kv message 'Installed package check failed'
		return 0
	fi

	if [ -x /etc/init.d/rpcd ]; then
		/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	fi
	if [ -x /etc/init.d/uhttpd ]; then
		/etc/init.d/uhttpd reload >/dev/null 2>&1 || true
	fi

	log_kv component mainprogram
	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv package_manager "$package_manager"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset "$asset"
	log_kv can_upgrade 0
	log_kv message 'Upgrade completed'
	return 0
}

xray_info() {
	local pm current installed latest_output latest_rc latest_version arch asset can_upgrade

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	asset=""
	if current="$(get_xray_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_xray_latest_info 2>/dev/null)"
	latest_rc=$?

	log_kv component xray
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset "$asset"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			2) log_kv error 'unsupported_package_manager' ;;
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		 esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	pm="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	arch="$(printf '%s\n' "$latest_output" | sed -n 's/^arch=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

mihomo_info() {
	local pm current installed latest_output latest_rc latest_version arch asset can_upgrade

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	asset=""
	if current="$(get_mihomo_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_mihomo_latest_info 2>/dev/null)"
	latest_rc=$?

	log_kv component mihomo
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset "$asset"

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			2) log_kv error 'unsupported_package_manager' ;;
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		 esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	pm="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	arch="$(printf '%s\n' "$latest_output" | sed -n 's/^arch=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ] || version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

naiveproxy_info() {
	local pm current installed latest_output latest_rc latest_version arch asset can_upgrade

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	if current="$(get_naiveproxy_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	latest_output="$(get_naiveproxy_latest_info 2>/dev/null)"
	latest_rc=$?

	log_kv component naiveproxy
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset ''

	if [ $latest_rc -ne 0 ]; then
		log_kv can_upgrade 0
		case "$latest_rc" in
			2) log_kv error 'unsupported_package_manager' ;;
			3) log_kv error 'fetch_failed' ;;
			4) log_kv error 'asset_not_found' ;;
			*) log_kv error 'unknown_error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	pm="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	arch="$(printf '%s\n' "$latest_output" | sed -n 's/^arch=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	can_upgrade=0
	if [ -z "$current" ]; then
		can_upgrade=1
	elif ! naiveproxy_versions_equal "$latest_version" "$current" && version_gt "$latest_version" "$current"; then
		can_upgrade=1
	fi

	printf '%s\n' "$latest_output" | sed '/^download_url=/d'
	log_kv can_upgrade "$can_upgrade"
	log_kv error ''
}

xray_local_info() {
	local pm current installed arch

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	if current="$(get_xray_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component xray
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset ''
	log_kv can_upgrade 0
	log_kv error ''
}

mihomo_local_info() {
	local pm current installed arch

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	if current="$(get_mihomo_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component mihomo
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset ''
	log_kv can_upgrade 0
	log_kv error ''
}

naiveproxy_local_info() {
	local pm current installed arch

	installed=0
	current=""
	pm="$(detect_package_manager 2>/dev/null || true)"
	arch="$(get_openwrt_arch)"
	if current="$(get_naiveproxy_current_version)" && [ -n "$current" ]; then
		installed=1
	fi

	log_kv component naiveproxy
	log_kv installed "$installed"
	log_kv current_version "$current"
	log_kv latest_version ''
	log_kv package_manager "$pm"
	log_kv arch "$arch"
	log_kv asset ''
	log_kv can_upgrade 0
	log_kv error ''
}

xray_upgrade() {
	local latest_output latest_rc latest_version download_url package_manager asset tmp_dir package_file current_before current_after

	latest_output="$(get_xray_latest_info 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			2) log_kv message 'Unsupported package manager' ;;
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		 esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	package_manager="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	current_before="$(get_xray_current_version 2>/dev/null || true)"
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi

	tmp_dir="$(mktemp -d /tmp/ssrplus-xray.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	package_file="$tmp_dir/$asset"
	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$package_file"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$package_file" ] || ! mainprogram_install_package "$package_manager" "$package_file"; then
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	current_after="$(get_xray_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		log_kv success 0
		log_kv message 'Installed package check failed'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv package_manager "$package_manager"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset "$asset"
	log_kv message 'Upgrade completed'
	return 0
}

mihomo_upgrade() {
	local latest_output latest_rc latest_version download_url package_manager asset tmp_dir package_file current_before current_after

	latest_output="$(get_mihomo_latest_info 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			2) log_kv message 'Unsupported package manager' ;;
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		 esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	package_manager="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	current_before="$(get_mihomo_current_version 2>/dev/null || true)"
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi

	tmp_dir="$(mktemp -d /tmp/ssrplus-mihomo.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	package_file="$tmp_dir/$asset"
	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$package_file"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$package_file" ] || ! mainprogram_install_package "$package_manager" "$package_file"; then
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	current_after="$(get_mihomo_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		log_kv success 0
		log_kv message 'Installed package check failed'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv package_manager "$package_manager"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset "$asset"
	log_kv message 'Upgrade completed'
	return 0
}

naiveproxy_upgrade() {
	local latest_output latest_rc latest_version download_url package_manager asset tmp_dir package_file current_before current_after

	latest_output="$(get_naiveproxy_latest_info 2>/dev/null)"
	latest_rc=$?
	if [ $latest_rc -ne 0 ]; then
		log_kv success 0
		case "$latest_rc" in
			2) log_kv message 'Unsupported package manager' ;;
			3) log_kv message 'Failed to fetch release metadata' ;;
			4) log_kv message 'Matching release asset not found' ;;
			*) log_kv message 'Unknown error' ;;
		esac
		return 0
	fi

	latest_version="$(printf '%s\n' "$latest_output" | sed -n 's/^latest_version=//p' | sed -n '1p')"
	download_url="$(printf '%s\n' "$latest_output" | sed -n 's/^download_url=//p' | sed -n '1p')"
	package_manager="$(printf '%s\n' "$latest_output" | sed -n 's/^package_manager=//p' | sed -n '1p')"
	asset="$(printf '%s\n' "$latest_output" | sed -n 's/^asset=//p' | sed -n '1p')"
	current_before="$(get_naiveproxy_current_version 2>/dev/null || true)"
	if [ -n "$current_before" ] && ! version_gt "$latest_version" "$current_before"; then
		log_kv success 1
		log_kv previous_version "$current_before"
		log_kv current_version "$current_before"
		log_kv latest_version "$latest_version"
		log_kv message 'Already up to date'
		return 0
	fi

	tmp_dir="$(mktemp -d /tmp/ssrplus-naiveproxy.XXXXXX)"
	if [ -z "$tmp_dir" ] || [ ! -d "$tmp_dir" ]; then
		log_kv success 0
		log_kv message 'Failed to create temp directory'
		return 0
	fi

	package_file="$tmp_dir/$asset"
	trap "rm -rf '$tmp_dir'" EXIT INT TERM

	if ! download_file "$download_url" "$package_file"; then
		log_kv success 0
		log_kv message 'Download failed'
		return 0
	fi

	if [ ! -s "$package_file" ] || ! mainprogram_install_package "$package_manager" "$package_file"; then
		log_kv success 0
		log_kv message 'Install failed'
		return 0
	fi

	current_after="$(get_naiveproxy_current_version 2>/dev/null || true)"
	if [ -z "$current_after" ]; then
		log_kv success 0
		log_kv message 'Installed package check failed'
		return 0
	fi

	if [ -x /etc/init.d/shadowsocksr ]; then
		/etc/init.d/shadowsocksr restart >/dev/null 2>&1 || true
	fi

	log_kv success 1
	log_kv previous_version "$current_before"
	log_kv current_version "$current_after"
	log_kv latest_version "$latest_version"
	log_kv package_manager "$package_manager"
	log_kv arch "$(get_openwrt_arch)"
	log_kv asset "$asset"
	log_kv message 'Upgrade completed'
	return 0
}

# ==================== 主程序入口 ====================
case "${1:-}" in
	# 主程序相关
	mainprogram_info)
		mainprogram_info
		;;
	mainprogram_local_info)
		mainprogram_local_info
		;;
	mainprogram_upgrade)
		mainprogram_upgrade
		;;
	# Xray 相关
	xray_info)
		xray_info
		;;
	xray_local_info)
		xray_local_info
		;;
	xray_upgrade)
		xray_upgrade
		;;
	# Mihomo 相关
	mihomo_info)
		mihomo_info
		;;
	mihomo_local_info)
		mihomo_local_info
		;;
	mihomo_upgrade)
		mihomo_upgrade
		;;
	# Naiveproxy 相关
	naiveproxy_info)
		naiveproxy_info
		;;
	naiveproxy_local_info)
		naiveproxy_local_info
		;;
	naiveproxy_upgrade)
		naiveproxy_upgrade
		;;
	# Country MMDB 相关
	country_mmdb_info)
		country_mmdb_info
		;;
	country_mmdb_local_info)
		country_mmdb_local_info
		;;
	country_mmdb_upgrade)
		country_mmdb_upgrade
		;;
	# Geosite (OpenClash) 相关
	geosite_info)
		geosite_info
		;;
	geosite_local_info)
		geosite_local_info
		;;
	geosite_upgrade)
		geosite_upgrade
		;;
	# V2Ray GeoIP 相关
	v2ray_geoip_info)
		v2ray_geoip_info
		;;
	v2ray_geoip_local_info)
		v2ray_geoip_local_info
		;;
	v2ray_geoip_upgrade)
		v2ray_geoip_upgrade
		;;
	# V2Ray Geosite 相关
	v2ray_geosite_info)
		v2ray_geosite_info
		;;
	v2ray_geosite_local_info)
		v2ray_geosite_local_info
		;;
	v2ray_geosite_upgrade) 
		v2ray_geosite_upgrade
		;;
	*)
		log_kv success 0
		log_kv message 'Usage: update_components.sh mainprogram_info|mainprogram_local_info|mainprogram_upgrade|xray_info|xray_local_info|xray_upgrade|mihomo_info|mihomo_local_info|mihomo_upgrade|naiveproxy_info|naiveproxy_local_info|naiveproxy_upgrade|country_mmdb_info|country_mmdb_local_info|country_mmdb_upgrade|geosite_info|geosite_local_info|geosite_upgrade|v2ray_geoip_info|v2ray_geoip_local_info|v2ray_geoip_upgrade|v2ray_geosite_info|v2ray_geosite_local_info|v2ray_geosite_upgrade'
		return 1 2>/dev/null || exit 1
		;;
esac
