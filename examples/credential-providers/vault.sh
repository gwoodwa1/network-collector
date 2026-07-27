#!/usr/bin/env bash
set -euo pipefail

: "${VAULT_KV_MOUNT:?set VAULT_KV_MOUNT to the KV secrets-engine mount}"
: "${VAULT_KV_PREFIX:?set VAULT_KV_PREFIX to the parent credential path}"

secret_name="${NET_CREDENTIAL_PROFILE:-${NET_TARGET_HOSTNAME:-}}"
if [[ -z "${secret_name}" ]]; then
  echo "credential target did not provide a profile or hostname" >&2
  exit 1
fi

secret_json="$(
  vault kv get \
    -format=json \
    -mount="${VAULT_KV_MOUNT}" \
    "${VAULT_KV_PREFIX%/}/${secret_name}"
)"

jq -ce '
  (.data.data // .data) as $secret
  | {username: $secret.username, password: $secret.password}
  | select(
      (.username | type == "string" and length > 0)
      and (.password | type == "string" and length > 0)
    )
' <<<"${secret_json}"
