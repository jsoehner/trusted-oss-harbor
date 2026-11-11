#!/usr/bin/env bash
# ==============================================================================
# Generate mTLS PKI for pfSense & GitHub Actions Client Authentication
# ==============================================================================
set -euo pipefail

OUT_DIR="${1:-./mtls-pki}"
mkdir -p "${OUT_DIR}"
chmod 0700 "${OUT_DIR}"

echo "[INFO] Generating CA private key and certificate..."
openssl req -x509 -newkey rsa:4096 -sha384 -days 3650 -nodes \
  -keyout "${OUT_DIR}/ca.key" \
  -out "${OUT_DIR}/ca.crt" \
  -subj "/C=CA/ST=Ontario/L=Local/O=JSI Group/OU=Security/CN=Trusted-OSS-GitHub-Client-CA"

chmod 0600 "${OUT_DIR}/ca.key"
chmod 0644 "${OUT_DIR}/ca.crt"

echo "[INFO] Generating Client private key and CSR..."
openssl req -newkey rsa:4096 -sha384 -nodes \
  -keyout "${OUT_DIR}/client.key" \
  -out "${OUT_DIR}/client.csr" \
  -subj "/C=CA/ST=Ontario/L=Local/O=JSI Group/OU=GitHubActions/CN=github-actions-runner-client"

chmod 0600 "${OUT_DIR}/client.key"

echo "[INFO] Signing Client certificate with CA..."
cat << 'EOF' > "${OUT_DIR}/client_ext.cnf"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "${OUT_DIR}/client.csr" \
  -CA "${OUT_DIR}/ca.crt" \
  -CAkey "${OUT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${OUT_DIR}/client.crt" \
  -days 1095 \
  -sha384 \
  -extfile "${OUT_DIR}/client_ext.cnf"

chmod 0644 "${OUT_DIR}/client.crt"
rm -f "${OUT_DIR}/client.csr" "${OUT_DIR}/client_ext.cnf"

echo "[INFO] Creating PKCS#12 bundle for Java/Maven..."
openssl pkcs12 -export \
  -in "${OUT_DIR}/client.crt" \
  -inkey "${OUT_DIR}/client.key" \
  -out "${OUT_DIR}/client.p12" \
  -name "github-actions-runner-client" \
  -passout pass:changeit

chmod 0600 "${OUT_DIR}/client.p12"

echo "================================================================================"
echo "✅ mTLS PKI Generation Complete in: ${OUT_DIR}"
echo "================================================================================"
echo "1. pfSense Import File (Upload this as Internal CA in pfSense Cert Manager):"
echo "   -> ${OUT_DIR}/ca.crt"
echo ""
echo "2. GitHub Action Repository Secret (OSS_MTLS_CLIENT_CERT):"
echo "   -> ${OUT_DIR}/client.crt"
echo ""
echo "3. GitHub Action Repository Secret (OSS_MTLS_CLIENT_KEY):"
echo "   -> ${OUT_DIR}/client.key"
echo ""
echo "4. PKCS#12 Bundle (Password: 'changeit') for Java / Maven:"
echo "   -> ${OUT_DIR}/client.p12"
echo "================================================================================"
