#!/bin/sh

# author: starsunyzl
# see https://github.com/starsunyzl/ddns-scripts-alibabacloud for more details

. /usr/share/libubox/jshn.sh

[ -z "$CURL" ] && [ -z "$CURL_SSL" ] && write_log 14 "AlibabaCloud communication require cURL with SSL support. Please install"
[ -z "$domain" ] && write_log 14 "Service section not configured correctly! Missing 'domain'"
[ -z "$username" ] && write_log 14 "Service section not configured correctly! Missing AccessKey ID as 'username'"
[ -z "$password" ] && write_log 14 "Service section not configured correctly! Missing AccessKey Secret as 'password'"
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

url_encode() {
	local __ENCODED
	__ENCODED="$(awk -v str="$1" 'BEGIN{ORS="";for(i=32;i<=127;i++)lookup[sprintf("%c",i)]=i
		for(k=1;k<=length(str);++k){enc=substr(str,k,1);if(enc!~"[-_.~a-zA-Z0-9]")enc=sprintf("%%%02X", lookup[enc]);print enc}}')"
  printf %s "$__ENCODED"
}

percent_encode() {
  local __ENCODED="$(url_encode $1)"
  __ENCODED="${__ENCODED//+/%20}"
  __ENCODED="${__ENCODED//\*/%2A}"
  __ENCODED="${__ENCODED//%7E/\~}"
  printf %s "$__ENCODED"
}

sign() {
  local __KEY="$1"  # AccessKey Secret
  local __MSG="$2"  # Canonicalized Query String

  local __STRING_TO_SIGN="POST&%2F&$(percent_encode $__MSG)"
  printf %s "$__STRING_TO_SIGN" | openssl sha1 -hmac "$__KEY&" -binary | openssl base64
}

alibabacloud_transfer() {
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
  write_log 12 "Error in 'alibabacloud_transfer()' - program coding error"
}

local __REQUEST_URL="https://alidns.aliyuncs.com"
local __REQUEST_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
local __UUID="$(cat /proc/sys/kernel/random/uuid)"
# All plaintext parameters are pre-sorted and pre-encoded, we only use two APIs, no need to sort in the shell script...Well, actually I'm too lazy to do it
local __REQUEST_BODY_FMT="AccessKeyId=%s&Action=DescribeSubDomainRecords&DomainName=%s&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce=%s&SignatureVersion=1.0&SubDomain=%s&Timestamp=%s&Type=%s&Version=2015-01-09"
local __CANONICALIZED_QUERY_STRING="$(printf "$__REQUEST_BODY_FMT" "$(percent_encode "$__SECRET_ID")" "$(percent_encode "$__DOMAIN")" "$(percent_encode "$__UUID")" "$(percent_encode "$__HOST.$__DOMAIN")" "$(percent_encode "$__REQUEST_TIMESTAMP")" "$(percent_encode "$__RECORD_TYPE")")"
local __SIGNATURE="$(sign "$__SECRET_KEY" "$__CANONICALIZED_QUERY_STRING")"
local __REQUEST_BODY="$(printf "$__REQUEST_BODY_FMT&Signature=%s" "$(url_encode "$__SECRET_ID")" "$(url_encode "$__DOMAIN")" "$(url_encode "$__UUID")" "$(url_encode "$__HOST.$__DOMAIN")" "$(url_encode "$__REQUEST_TIMESTAMP")" "$(url_encode "$__RECORD_TYPE")" "$(url_encode "$__SIGNATURE")")"

alibabacloud_transfer "$__REQUEST_URL" "-d '$__REQUEST_BODY'" || return 1

write_log 7 "DescribeSubDomainRecords answered:\n$(cat $DATFILE)"

json_init
json_load_file $DATFILE

local __CODE
json_get_var __CODE Code
[ -n "$__CODE" ] && return 1

local __LIST_IDX=1
local __RECORD_ID_TMP __RECORD_VALUE
json_select DomainRecords
if json_is_a Record array; then
  json_select Record
  while json_is_a $__LIST_IDX object; do
    json_select $__LIST_IDX
    json_get_var __RECORD_ID_TMP RecordId
    write_log 7 "RecordId: $__RECORD_ID_TMP"

    json_get_var __RECORD_VALUE Value
    write_log 7 "RecordValue: $__RECORD_VALUE"

    json_select ..
    __LIST_IDX=$(( __LIST_IDX + 1 ))

    [ -n "$__RECORD_ID" -a "$__RECORD_ID" = "$__RECORD_ID_TMP" ] && break
  done
fi

[ -z "$__RECORD_ID_TMP" ] && {
  write_log 3 "Failed to get RecordId"
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

__REQUEST_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
__UUID="$(cat /proc/sys/kernel/random/uuid)"
__REQUEST_BODY_FMT="AccessKeyId=%s&Action=UpdateDomainRecord&Format=JSON&RR=%s&RecordId=%s&SignatureMethod=HMAC-SHA1&SignatureNonce=%s&SignatureVersion=1.0&Timestamp=%s&Type=%s&Value=%s&Version=2015-01-09"
__CANONICALIZED_QUERY_STRING="$(printf "$__REQUEST_BODY_FMT" "$(percent_encode "$__SECRET_ID")" "$(percent_encode "$__HOST")" "$(percent_encode "$__RECORD_ID")" "$(percent_encode "$__UUID")" "$(percent_encode "$__REQUEST_TIMESTAMP")" "$(percent_encode "$__RECORD_TYPE")" "$(percent_encode "$__IP")")"
__SIGNATURE="$(sign "$__SECRET_KEY" "$__CANONICALIZED_QUERY_STRING")"
__REQUEST_BODY="$(printf "$__REQUEST_BODY_FMT&Signature=%s" "$(url_encode "$__SECRET_ID")" "$(url_encode "$__HOST")" "$(url_encode "$__RECORD_ID")" "$(url_encode "$__UUID")" "$(url_encode "$__REQUEST_TIMESTAMP")" "$(url_encode "$__RECORD_TYPE")" "$(url_encode "$__IP")" "$(url_encode "$__SIGNATURE")")"

alibabacloud_transfer "$__REQUEST_URL" "-d '$__REQUEST_BODY'" || return 1

write_log 7 "UpdateDomainRecord answered:\n$(cat $DATFILE)"

json_init
json_load_file $DATFILE

json_get_var __CODE Code
[ -n "$__CODE" ] && return 1

json_get_var __RECORD_ID_TMP RecordId
[ -n "$__RECORD_ID_TMP" ] && return 0 || return 1
