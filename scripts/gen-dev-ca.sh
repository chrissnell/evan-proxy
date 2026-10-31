#!/usr/bin/env bash
#
# Generates a throwaway ECDSA P-256 root CA for the Phase 1 MITM block page,
# plus the mobileconfig that installs it on a test device.
#
# This CA is for the proof of concept only. Phase 3 replaces it with a CA
# generated on first boot and held in Vault. The key written here is
# unencrypted and lives in scratch/ (gitignored) — do not ship it.
#
#   ./scripts/gen-dev-ca.sh [output-dir]   # default: scratch/
#
# Then run the proxy with:
#   MITM_ENABLED=true \
#   MITM_CA_CERT_FILE=scratch/dev-ca.crt \
#   MITM_CA_KEY_FILE=scratch/dev-ca.key \
#   ./evan-proxy
set -euo pipefail

OUT_DIR="${1:-scratch}"
CN="${MITM_CA_CN:-evan-proxy dev CA}"
DAYS="${MITM_CA_DAYS:-3650}"

mkdir -p "$OUT_DIR"
KEY="$OUT_DIR/dev-ca.key"
CRT="$OUT_DIR/dev-ca.crt"

if [[ -e "$KEY" || -e "$CRT" ]]; then
	echo "refusing to overwrite existing $KEY / $CRT — delete them first" >&2
	exit 1
fi

# basicConstraints CA:true and keyUsage keyCertSign are both required: pkg/mitm
# rejects a CA certificate missing either, and iOS will not chain through one.
CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT
cat >"$CONF" <<EOF
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

[dn]
CN = ${CN}

[v3_ca]
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$KEY"
chmod 600 "$KEY"
openssl req -new -x509 -key "$KEY" -out "$CRT" -days "$DAYS" -sha256 -config "$CONF"

echo "CA certificate: $CRT"
echo "CA private key: $KEY"
openssl x509 -in "$CRT" -noout -subject -dates -fingerprint -sha256

"$(dirname "$0")/gen-ca-mobileconfig.sh" "$CRT" >"$OUT_DIR/dev-ca.mobileconfig"
echo "mobileconfig:   $OUT_DIR/dev-ca.mobileconfig"
