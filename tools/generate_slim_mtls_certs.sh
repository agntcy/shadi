#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${1:-./tmp/shadi-slim-mtls}"
DAYS="${DAYS:-365}"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

rm -f \
  ca.key ca.crt ca.srl \
  server.key server.csr server.crt server.ext client.ext \
  client-secops-a.key client-secops-a.csr client-secops-a.crt \
  client-secops-b.key client-secops-b.csr client-secops-b.crt \
  client-avatar.key client-avatar.csr client-avatar.crt

MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.crt -days "$DAYS" \
  -subj "/CN=SHADI SLIM CA"

MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost"

cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -extfile server.ext

MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes \
  -keyout client-secops-a.key -out client-secops-a.csr -subj "/CN=secops-a"

openssl x509 -req -in client-secops-a.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client-secops-a.crt -days "$DAYS" -extfile client.ext

MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes \
  -keyout client-secops-b.key -out client-secops-b.csr -subj "/CN=secops-b"

openssl x509 -req -in client-secops-b.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client-secops-b.crt -days "$DAYS" -extfile client.ext

MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes \
  -keyout client-avatar.key -out client-avatar.csr -subj "/CN=avatar"

openssl x509 -req -in client-avatar.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client-avatar.crt -days "$DAYS" -extfile client.ext

echo "Generated mTLS certs in $CERT_DIR"
