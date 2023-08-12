#!/bin/sh

# author: starsunyzl
# see https://github.com/starsunyzl/ddns-scripts-dnspod for more details

. /usr/share/libubox/jshn.sh

[ -z "$CURL" ] && [ -z "$CURL_SSL" ] && write_log 14 "DNSPod communication require cURL with SSL support. Please install"
[ -z "$domain" ] && write_log 14 "Service section not configured correctly! Missing 'domain'"
[ -z "$username" ] && write_log 14 "Service section not configured correctly! Missing SecretId as 'username'"
[ -z "$password" ] && write_log 14 "Service section not configured correctly! Missing SecretKey as 'password'"
[ $use_https -eq 0 ] && use_https=1  # force HTTPS

# split __HOST __DOMAIN from $domain
# given data:
# example.com or @example.com for "domain record"
# host.sub@example.com for a "host record"
local __HOST="$(printf %s "$domain" | cut -d@ -f1)"
local __DOMAIN="$(printf %s "$domain" | cut -d@ -f2)"

# __DOMAIN = the base domain i.e. example.com
# __HOST   = host.sub if updating a host record or
# __HOST   = "@" for a domain record
[ -z "$__HOST" -o "$__HOST" = "$__DOMAIN" ] && __HOST="@"

local __SECRET_ID="$username"
local __SECRET_KEY="$password"
local __RECORD_ID="$param_enc"
local __RECORD_TYPE="A"
[ $use_ipv6 -eq 1 ] && __RECORD_TYPE="AAAA"

sha256() {
  local __MSG="$1"
  printf "$__MSG" | openssl sha256 | sed "s/^.* //"
}

hmac_sha256_plainkey() {
  local __KEY="$1"
  local __MSG="$2"
  printf "$__MSG" | openssl sha256 -hmac "$__KEY" | sed "s/^.* //"
}

hmac_sha256_hexkey() {
  local __KEY="$1"
  local __MSG="$2"
  printf "$__MSG" | openssl sha256 -mac hmac -macopt "hexkey:$__KEY" | sed "s/^.* //"
}

build_request_param() {
  # API function name and JSON parameters
  local __REQUEST_ACTION="$1"
  local __REQUEST_BODY="$2"

  # __REQUEST_HOST and __REQUEST_CONTENT_TYPE must be lowercase
  # Generally all APIs under the same __REQUEST_SERVICE have the same __REQUEST_VERSION,
  # if they are different, you need to put __REQUEST_VERSION in the parameter of this function
  local __REQUEST_HOST="dnspod.tencentcloudapi.com"
  local __REQUEST_SERVICE="dnspod"
  local __REQUEST_VERSION="2021-03-23"
  local __REQUEST_CONTENT_TYPE="application/json"  # ; charset=utf-8
  local __REQUEST_DATE="$(date -u +%Y-%m-%d)"
  local __REQUEST_TIMESTAMP="$(date -u +%s)"

  local __HASHED_REQUEST_PAYLOAD="$(sha256 "$__REQUEST_BODY")"
  local __CANONICAL_REQUEST="$(cat <<EOF
POST
/

content-type:$__REQUEST_CONTENT_TYPE
host:$__REQUEST_HOST

content-type;host
$__HASHED_REQUEST_PAYLOAD
EOF
)"
  local __HASHED_CANONICAL_REQUEST="$(sha256 "$__CANONICAL_REQUEST")"
  local __STRING_TO_SIGN="$(cat <<EOF
TC3-HMAC-SHA256
$__REQUEST_TIMESTAMP
$__REQUEST_DATE/$__REQUEST_SERVICE/tc3_request
$__HASHED_CANONICAL_REQUEST
EOF
)"

  local __SECRET_DATE="$(hmac_sha256_plainkey "TC3$__SECRET_KEY" "$__REQUEST_DATE")"
  local __SECRET_SERVICE="$(hmac_sha256_hexkey "$__SECRET_DATE" "$__REQUEST_SERVICE")"
  local __SECRET_SIGNING="$(hmac_sha256_hexkey "$__SECRET_SERVICE" "tc3_request")"
  local __SIGNATURE="$(hmac_sha256_hexkey "$__SECRET_SIGNING" "$__STRING_TO_SIGN")"

  local __AUTHORIZATION="TC3-HMAC-SHA256 Credential=$__SECRET_ID/$__REQUEST_DATE/$__REQUEST_SERVICE/tc3_request, SignedHeaders=content-type;host, Signature=$__SIGNATURE"

  local __REQUEST_PARAM="-H 'Authorization: $__AUTHORIZATION' -H 'Content-Type: $__REQUEST_CONTENT_TYPE' -H 'Host: $__REQUEST_HOST' -H 'X-TC-Action: $__REQUEST_ACTION' -H 'X-TC-Version: $__REQUEST_VERSION' -H 'X-TC-Timestamp: $__REQUEST_TIMESTAMP' -d '$__REQUEST_BODY'"
  printf %s "$__REQUEST_PARAM"
}

dnspod_transfer() {
  local __URL="$1"
  local __PARAM="$2"
  local __ERR=0
  local __CNT=0  # error counter
  local __PROG __RUNPROG

  # Use ip_network as default for bind_network if not separately specified
  [ -z "$bind_network" ] && [ "$ip_source" = "network" ] && [ "$ip_network" ] && bind_network="$ip_network"

  __PROG="$CURL -RsS -o $DATFILE --stderr $ERRFILE"
  __PROG="$__PROG $__PARAM"
  # check HTTPS support
  [ -z "$CURL_SSL" -a $use_https -eq 1 ] && \
    write_log 13 "cURL: libcurl compiled without https support"
  # force network/interface-device to use for communication
  if [ -n "$bind_network" ]; then
    local __DEVICE
    network_get_device __DEVICE $bind_network || \
      write_log 13 "Can not detect local device using 'network_get_device $bind_network' - Error: '$?'"
    write_log 7 "Force communication via device '$__DEVICE'"
    __PROG="$__PROG --interface $__DEVICE"
  fi
  # force ip version to use
  if [ $force_ipversion -eq 1 ]; then
    [ $use_ipv6 -eq 0 ] && __PROG="$__PROG -4" || __PROG="$__PROG -6"  # force IPv4/IPv6
  fi
  # set certificate parameters
  if [ $use_https -eq 1 ]; then
    if [ "$cacert" = "IGNORE" ]; then  # idea from Ticket #15327 to ignore server cert
      __PROG="$__PROG --insecure"  # but not empty better to use "IGNORE"
    elif [ -f "$cacert" ]; then
      __PROG="$__PROG --cacert $cacert"
    elif [ -d "$cacert" ]; then
      __PROG="$__PROG --capath $cacert"
    elif [ -n "$cacert" ]; then    # it's not a file and not a directory but given
      write_log 14 "No valid certificate(s) found at '$cacert' for HTTPS communication"
    fi
  fi
  # disable proxy if no set (there might be .wgetrc or .curlrc or wrong environment set)
  # or check if libcurl compiled with proxy support
  if [ -z "$proxy" ]; then
    __PROG="$__PROG --noproxy '*'"
  elif [ -z "$CURL_PROXY" ]; then
    # if libcurl has no proxy support and proxy should be used then force ERROR
    write_log 13 "cURL: libcurl compiled without Proxy support"
  fi

  __RUNPROG="$__PROG '$__URL'"  # build final command
  __PROG="cURL"      # reuse for error logging

  while : ; do
    write_log 7 "#> $__RUNPROG"
    eval $__RUNPROG      # DO transfer
    __ERR=$?      # save error code
    [ $__ERR -eq 0 ] && return 0  # no error leave
    [ -n "$LUCI_HELPER" ] && return 1  # no retry if called by LuCI helper script

    write_log 3 "$__PROG Error: '$__ERR'"
    write_log 7 "$(cat $ERRFILE)"    # report error

    [ $VERBOSE -gt 1 ] && {
      # VERBOSE > 1 then NO retry
      write_log 4 "Transfer failed - Verbose Mode: $VERBOSE - NO retry on error"
      return 1
    }

    __CNT=$(( $__CNT + 1 ))  # increment error counter
    # if error count > retry_count leave here
    [ $retry_count -gt 0 -a $__CNT -gt $retry_count ] && \
      write_log 14 "Transfer failed after $retry_count retries"

    write_log 4 "Transfer failed - retry $__CNT/$retry_count in $RETRY_SECONDS seconds"
    sleep $RETRY_SECONDS &
    PID_SLEEP=$!
    wait $PID_SLEEP  # enable trap-handler
    PID_SLEEP=0
  done
  # we should never come here there must be a programming error
  write_log 12 "Error in 'dnspod_transfer()' - program coding error"
}

local __REQUEST_URL="https://dnspod.tencentcloudapi.com"
local __REQUEST_BODY="{\"Domain\": \"$__DOMAIN\", \"Subdomain\": \"$__HOST\", \"RecordType\": \"$__RECORD_TYPE\"}"
local __REQUEST_PARAM="$(build_request_param "DescribeRecordList" "$__REQUEST_BODY")"

dnspod_transfer "$__REQUEST_URL" "$__REQUEST_PARAM" || return 1

write_log 7 "DescribeRecordList answered:\n$(cat $DATFILE)"

json_init
json_load_file $DATFILE

local __ERROR
json_select Response
json_get_var __ERROR Error
[ -n "$__ERROR" ] && return 1

local __LIST_IDX=1
local __RECORD_ID_TMP __RECORD_VALUE __RECORD_LINE_ID
if json_is_a RecordList array; then
  json_select RecordList
  while json_is_a $__LIST_IDX object; do
    json_select $__LIST_IDX
    json_get_var __RECORD_ID_TMP RecordId
    write_log 7 "RecordId: $__RECORD_ID_TMP"

    json_get_var __RECORD_VALUE Value
    write_log 7 "RecordValue: $__RECORD_VALUE"

    json_get_var __RECORD_LINE_ID LineId
    write_log 7 "RecordLineId: $__RECORD_LINE_ID"

    json_select ..
    __LIST_IDX=$(( __LIST_IDX + 1 ))

    [ -n "$__RECORD_ID" -a "$__RECORD_ID" = "$__RECORD_ID_TMP" ] && break
  done
fi

[ -z "$__RECORD_ID_TMP" -o -z "$__RECORD_LINE_ID" ] && {
  write_log 3 "Failed to get RecordId or RecordLineId"
  return 1
}

if [ -z "$__RECORD_ID" ]; then
  if [ $__LIST_IDX -gt 2 ]; then
    write_log 3 "Get multiple RecordId, one of which must be configured in the 'param_enc' option"
    return 1
  fi
  __RECORD_ID="$__RECORD_ID_TMP"
elif [ "$__RECORD_ID" != "$__RECORD_ID_TMP" ]; then
  write_log 3 "The configured RecordId was not found in the fetched record"
  return 1
fi

[ -n "$__RECORD_VALUE" -a "$__RECORD_VALUE" = "$__IP" ] && {
  write_log 6 "IP is already up to date"
  return 0
}

# RecordLineId is a string type
__REQUEST_BODY="{\"Domain\": \"$__DOMAIN\", \"SubDomain\": \"$__HOST\", \"RecordLine\": \"unused\", \"RecordLineId\": \"$__RECORD_LINE_ID\", \"RecordId\": $__RECORD_ID, \"RecordType\": \"$__RECORD_TYPE\", \"Value\": \"$__IP\"}"
__REQUEST_PARAM="$(build_request_param "ModifyRecord" "$__REQUEST_BODY")"

>$DATFILE
>$ERRFILE
dnspod_transfer "$__REQUEST_URL" "$__REQUEST_PARAM" || return 1

write_log 7 "ModifyRecord answered:\n$(cat $DATFILE)"

json_init
json_load_file $DATFILE

json_select Response
json_get_var __ERROR Error
[ -n "$__ERROR" ] && return 1

json_get_var __RECORD_ID_TMP RecordId
[ -n "$__RECORD_ID_TMP" ] && return 0 || return 1
