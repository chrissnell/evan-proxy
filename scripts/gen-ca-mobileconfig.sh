#!/usr/bin/env bash
#
# Wraps a PEM CA certificate in an iOS/macOS configuration profile that installs
# it as a trusted root, and writes the profile to stdout.
#
#   ./scripts/gen-ca-mobileconfig.sh scratch/dev-ca.crt > scratch/dev-ca.mobileconfig
#
# AirDrop or email the result to the test device, install it, then turn the CA
# on under Settings → General → About → Certificate Trust Settings. iOS does NOT
# trust a manually installed root until that switch is flipped.
#
# Phase 1 only — Phase 4 pushes the CA through SimpleMDM instead, which skips
# both the manual install and the trust switch.
#
# The payload identifier and UUID are stable on purpose. Reusing them makes a
# later push *replace* the installed certificate; changing them would leave the
# old root trusted alongside the new one and pollute the trust store.
set -euo pipefail

CERT="${1:-}"
if [[ -z "$CERT" || ! -r "$CERT" ]]; then
	echo "usage: $0 <ca-cert.pem>" >&2
	exit 1
fi

PAYLOAD_ID="com.chrissnell.evanproxy.ca"
PAYLOAD_UUID="6F2B1E54-7C3A-4D18-9B0E-2A5C8D41F7B3"
PROFILE_ID="com.chrissnell.evanproxy.profile"
PROFILE_UUID="C41D9A07-58E6-4F2B-A13C-7E9048B6D250"

CN="$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline,-align,-esc_msb \
	| awk -F' = ' '/commonName/ {print $2}')"
CN="${CN:-evan-proxy CA}"

# PayloadContent for com.apple.security.root is the raw DER, base64-encoded.
DER_B64="$(openssl x509 -in "$CERT" -outform DER | base64 | tr -d '\n')"

cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadIdentifier</key>
			<string>${PAYLOAD_ID}</string>
			<key>PayloadUUID</key>
			<string>${PAYLOAD_UUID}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>${CN}</string>
			<key>PayloadDescription</key>
			<string>Root certificate for evan-proxy TLS inspection</string>
			<key>PayloadCertificateFileName</key>
			<string>evan-proxy-ca.cer</string>
			<key>PayloadContent</key>
			<data>${DER_B64}</data>
		</dict>
	</array>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadIdentifier</key>
	<string>${PROFILE_ID}</string>
	<key>PayloadUUID</key>
	<string>${PROFILE_UUID}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadDisplayName</key>
	<string>evan-proxy CA</string>
	<key>PayloadDescription</key>
	<string>Installs the evan-proxy root certificate.</string>
	<key>PayloadOrganization</key>
	<string>Snell Family</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
</dict>
</plist>
EOF
