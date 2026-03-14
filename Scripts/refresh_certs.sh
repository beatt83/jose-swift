#!/bin/bash

# Create test certificates for jose-swift
ORG_NAME="Beatt83"
ROOT_CN="Jose Swift Root CA"
INT_CN="Jose Swift Intermediate CA"
LEAF_CN="Jose Swift Leaf Certificate"
EXPIRY_DAYS=3650 

# --- The Cleanup Function ---
# This runs automatically on exit, even if the script fails.
cleanup() {
    echo -e "\n🧹 Cleaning up temporary artifacts..."
    rm -f *.key *.crt *.csr *.conf *.der *.txt *.raw *.srl
    echo "Done."
}
trap cleanup EXIT

echo "🔨 Generating Certificate Chain for $ORG_NAME..."

# 1. Root CA
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -new -x509 -sha256 -key root.key -out root.crt -subj "/O=$ORG_NAME/CN=$ROOT_CN" -days $EXPIRY_DAYS 2>/dev/null

# 2. Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out intermediate.key
openssl req -new -key intermediate.key -out intermediate.csr -subj "/O=$ORG_NAME/CN=$INT_CN" 2>/dev/null
echo "basicConstraints=critical,CA:TRUE" > ca.conf
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -out intermediate.crt -days $EXPIRY_DAYS -extfile ca.conf 2>/dev/null

# 3. Leaf Certificate
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -out leaf.csr -subj "/O=$ORG_NAME/CN=$LEAF_CN" 2>/dev/null
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out leaf.crt -days $EXPIRY_DAYS 2>/dev/null

echo "🖋️  Signing JWT..."

# 4. Python packaging (Handles Base64URL and ES256 Raw Signature)
python3 - <<EOF
import base64, json, subprocess

def b64url(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', '')

def get_cert_b64(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        return "".join([line.strip() for line in lines if "CERTIFICATE" not in line])

header = {
    "alg": "ES256",
    "typ": "JWT",
    "x5c": [get_cert_b64("leaf.crt"), get_cert_b64("intermediate.crt"), get_cert_b64("root.crt")]
}
payload = {"cool": True}

header_b64 = b64url(json.dumps(header).encode())
payload_b64 = b64url(json.dumps(payload).encode())
signing_input = f"{header_b64}.{payload_b64}".encode()

with open("signing_input.txt", "wb") as f: f.write(signing_input)
subprocess.run("openssl dgst -sha256 -sign leaf.key -out sig.der signing_input.txt", shell=True, capture_output=True)

with open("sig.der", "rb") as f:
    der = f.read()
    r_len = der[3]
    r = der[4:4+r_len][-32:]
    s_len = der[4+r_len+1]
    s = der[4+r_len+2:4+r_len+2+s_len][-32:]
    signature = b64url(r + s)

token = f"{header_b64}.{payload_b64}.{signature}"

print("\n" + "="*60)
print("  COPY THE BLOCK BELOW INTO YOUR SWIFT TEST")
print("="*60 + "\n")

print('let trusted = """')
with open("root.crt", "r") as f: print(f.read().strip())
print('"""\n')

print(f'let validToken = "{token}"')
EOF