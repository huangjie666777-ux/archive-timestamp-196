#!/usr/bin/env bash
# End-to-end demo: issue, verify offline, reject tampering.
# Requires the server running on TSA_URL (default http://127.0.0.1:8316).
set -euo pipefail

URL=${TSA_URL:-http://127.0.0.1:8316}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo 'archive digest demo payload' > doc.txt

echo '== 1. build query (sha256, request certs) =='
openssl ts -query -data doc.txt -sha256 -cert -out req.tsq

echo '== 2. POST to TSA =='
curl -sS -X POST "$URL/tsa" \
  -H 'Content-Type: application/timestamp-query' \
  --data-binary @req.tsq -o resp.tsr \
  -w 'HTTP %{http_code} %{content_type}\n'
openssl ts -reply -in resp.tsr -text | grep -E 'Status:|Serial|Time stamp|Policy|Nonce'

echo '== 3. fetch public chain and verify offline =='
curl -s "$URL/tsa/cert" -o chain.pem
awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > (n".crt")}' chain.pem
openssl ts -verify -data doc.txt -in resp.tsr -CAfile 2.crt -untrusted 1.crt

echo '== 4. tampered data is rejected =='
echo 'forged content' > evil.txt
if openssl ts -verify -data evil.txt -in resp.tsr -CAfile 2.crt -untrusted 1.crt; then
  echo 'ERROR: tampered data verified!' >&2; exit 1
else
  echo 'tampered data correctly rejected'
fi

echo '== 5. fetch stored receipt by serial =='
SERIAL=$(openssl ts -reply -in resp.tsr -text | awk '/Serial number/{print $3}')
curl -s "$URL/tsa/receipt/$((SERIAL))" -o receipt.tsr
cmp resp.tsr receipt.tsr && echo "receipt identical to original reply"

echo '== 6. unsupported hash is rejected with PKIStatusInfo =='
openssl ts -query -data doc.txt -sha1 -out bad.tsq
curl -sS -X POST "$URL/tsa" -H 'Content-Type: application/timestamp-query' \
  --data-binary @bad.tsq | openssl ts -reply -in /dev/stdin -text | grep 'Status:'
