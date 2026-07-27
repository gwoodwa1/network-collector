#!/usr/bin/env bash
set -euo pipefail

: "${CYBERARK_CCP_URL:?set CYBERARK_CCP_URL to the CCP AIMWebService Accounts endpoint}"
: "${CYBERARK_APP_ID:?set CYBERARK_APP_ID to the authorized application ID}"
: "${CYBERARK_SAFE:?set CYBERARK_SAFE to the credential safe}"

object_name="${NET_CREDENTIAL_PROFILE:-${NET_TARGET_HOSTNAME:-}}"
if [[ -z "${object_name}" ]]; then
  echo "credential target did not provide a profile or hostname" >&2
  exit 1
fi
if [[ -n "${CYBERARK_OBJECT_PREFIX:-}" ]]; then
  object_name="${CYBERARK_OBJECT_PREFIX}${object_name}"
fi

curl_args=(--fail --silent --show-error --get)
if [[ -n "${CYBERARK_CA_FILE:-}" ]]; then
  curl_args+=(--cacert "${CYBERARK_CA_FILE}")
fi
if [[ -n "${CYBERARK_CLIENT_CERT:-}" || -n "${CYBERARK_CLIENT_KEY:-}" ]]; then
  : "${CYBERARK_CLIENT_CERT:?set both CYBERARK_CLIENT_CERT and CYBERARK_CLIENT_KEY}"
  : "${CYBERARK_CLIENT_KEY:?set both CYBERARK_CLIENT_CERT and CYBERARK_CLIENT_KEY}"
  curl_args+=(--cert "${CYBERARK_CLIENT_CERT}" --key "${CYBERARK_CLIENT_KEY}")
fi

query="Safe=${CYBERARK_SAFE};Object=${object_name}"
if [[ -n "${CYBERARK_FOLDER:-}" ]]; then
  query="${query};Folder=${CYBERARK_FOLDER}"
fi
request_args=(
  --data-urlencode "AppID=${CYBERARK_APP_ID}"
  --data-urlencode "Query=${query}"
  --data-urlencode "QueryFormat=Exact"
)
if [[ -n "${CYBERARK_REASON:-}" ]]; then
  request_args+=(--data-urlencode "Reason=${CYBERARK_REASON}")
fi

response="$(
  curl "${curl_args[@]}" \
    "${request_args[@]}" \
    "${CYBERARK_CCP_URL}"
)"

jq -ce '
  {username: (.UserName // .username), password: (.Content // .password)}
  | select(
      (.username | type == "string" and length > 0)
      and (.password | type == "string" and length > 0)
    )
' <<<"${response}"
