#!/usr/bin/env bash
set -euo pipefail

: "${OP_VAULT:?set OP_VAULT to the permitted 1Password vault name or ID}"

item_name="${NET_CREDENTIAL_PROFILE:-${NET_TARGET_HOSTNAME:-}}"
if [[ -z "${item_name}" ]]; then
  echo "credential target did not provide a profile or hostname" >&2
  exit 1
fi
if [[ -n "${OP_ITEM_PREFIX:-}" ]]; then
  item_name="${OP_ITEM_PREFIX}${item_name}"
fi

username="$(op read "op://${OP_VAULT}/${item_name}/username")"
password="$(op read "op://${OP_VAULT}/${item_name}/password")"

jq -cn \
  --arg username "${username}" \
  --arg password "${password}" \
  'select(($username | length) > 0 and ($password | length) > 0)
   | {username: $username, password: $password}'
