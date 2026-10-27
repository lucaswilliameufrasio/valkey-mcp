#!/bin/sh
set -eu

attempt=0
issuer_authority=${OIDC_ISSUER_URL#*://}
issuer_authority=${issuer_authority%%/*}
issuer_path=$(printf '%s' "$OIDC_ISSUER_URL" | sed 's#^[^:]*://[^/]*##')
discovery_path="${issuer_path%/}/.well-known/openid-configuration"

until curl --fail --silent --show-error \
  --header "Host: $issuer_authority" \
  "${OIDC_BACKCHANNEL_URL%/}$discovery_path" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 180 ]; then
    printf '%s\n' 'Local OIDC provider did not become ready within 180 seconds.' >&2
    exit 1
  fi
  sleep 1
done

exec /usr/local/bin/valkey-mcp
