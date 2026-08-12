#!/usr/bin/env bash
# Generates the self-signed test certificate SslHostnameVerificationProof
# needs: a server keystore for the WRONG hostname ("attacker.invalid"), and a
# client truststore that trusts it (so the trust chain passes and hostname
# verification is the ONLY thing that can catch the mismatch). Regenerated
# fresh each run rather than committed -- these are throwaway local test
# certs, not secrets, but binary artifacts don't belong in source control
# when a few keytool calls reproduce them in under a second.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="$HERE/ssl-certs"
rm -rf "$DIR"; mkdir -p "$DIR"
cd "$DIR"

keytool -genkeypair -alias mitm -keyalg RSA -keysize 2048 -validity 3650 \
  -keystore server-keystore.p12 -storetype PKCS12 -storepass changeit -keypass changeit \
  -dname "CN=attacker.invalid, OU=test, O=test, L=test, ST=test, C=US" \
  -ext "SAN=dns:attacker.invalid" >/dev/null 2>&1

keytool -export -alias mitm -keystore server-keystore.p12 -storepass changeit \
  -file mitm.crt -rfc >/dev/null 2>&1

keytool -import -alias mitm -file mitm.crt -keystore client-truststore.p12 \
  -storetype PKCS12 -storepass changeit -noprompt >/dev/null 2>&1

echo "ssl-certs/ generated: server-keystore.p12 (CN=attacker.invalid), client-truststore.p12 (trusts it)"
