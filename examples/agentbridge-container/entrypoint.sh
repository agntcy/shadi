#!/bin/sh
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Run agentbridge register for the fake harness inside the SHADI sandbox.
#
# The A2A listener is HTTP+JSON on A2A_PORT. It binds 0.0.0.0, which
# agentbridge only allows over TLS, so a self-signed certificate is created
# when none is mounted. The agent card is also served over plain HTTP on
# CARD_PORT, which runtime discovery reads (the container's discovery labels
# are set by docker run / compose). Extra arguments are passed to register,
# e.g. --skill / --domain / --version, and --advertise-url with the published
# A2A port, so the card names an address clients can reach. Set the OASF
# server with OASF_SCHEMA_URL rather than --oasf-schema-url, so the sandbox
# allows it.
set -eu

A2A_PORT="${A2A_PORT:-8443}"
CARD_PORT="${CARD_PORT:-8081}"
TLS_DIR="${TLS_DIR:-$HOME/tls}"
# The OASF server that validates skills and domains, which the sandbox must
# reach: host[:port] from the URL, with the scheme's default port.
OASF_SCHEMA_URL="${OASF_SCHEMA_URL:-https://schema.oasf.outshift.com}"
oasf_authority="${OASF_SCHEMA_URL#*://}"
oasf_authority="${oasf_authority%%/*}"
case "$oasf_authority" in
  *:*) ;;
  *) case "$OASF_SCHEMA_URL" in http://*) oasf_authority="$oasf_authority:80" ;; *) oasf_authority="$oasf_authority:443" ;; esac ;;
esac

if [ -z "${A2A_TLS_CERT:-}" ]; then
  mkdir -p "$TLS_DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 -subj "/CN=${HOSTNAME:-agentbridge}" \
    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" >/dev/null 2>&1
  export A2A_TLS_CERT="$TLS_DIR/cert.pem" A2A_TLS_KEY="$TLS_DIR/key.pem"
fi

# The sandbox only reads what it is given: grant the profiles and the
# certificate and key directories, whether generated above or mounted, and
# let the listener write its local lease.
exec shadictl --net-block \
  --read "$AGENTBRIDGE_PROFILES_DIR" --allow "$SHADI_TMP_DIR" \
  --read "$(dirname "$A2A_TLS_CERT")" --read "$(dirname "$A2A_TLS_KEY")" \
  --net-allow "0.0.0.0:${A2A_PORT}" --net-allow "0.0.0.0:${CARD_PORT}" \
  --net-allow "$oasf_authority" \
  -- agentbridge register --tool fake-harness \
     --a2a-listen "0.0.0.0:${A2A_PORT}" --a2a-binding http+json \
     --card-listen "0.0.0.0:${CARD_PORT}" --oasf-schema-url "$OASF_SCHEMA_URL" "$@"
