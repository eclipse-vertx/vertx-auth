#!/bin/bash

#
# Copyright (c) 2011-2026 Contributors to the Eclipse Foundation
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
# which is available at https://www.apache.org/licenses/LICENSE-2.0.
#
# SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
#

# Generated with Gemini

###############################################################################
# UNDERSTANDING THE JSON FIELDS (JWK - RFC 7517)
#
# This script generates a mock Microsoft discovery file (azure-sample-keys.json)
# and a signed JWT (azure-sample-token.txt).
#
# Field | Description
# ------|----------------------------------------------------------------------
# kid   | Key ID: Must match the 'kid' in the JWT header. Used to find the key.
# kty   | Key Type: Set to 'RSA'.
# use   | Public Key Use: Set to 'sig' (signature).
# n     | Modulus: The "large number" part of the RSA public key (Base64Url).
# e     | Exponent: The RSA public exponent, usually 'AQAB' (decimal 65537).
# x5c   | Cert Chain: Base64-encoded X.509 certificate (Standard Base64).
# x5t   | Thumbprint: SHA-1 hash of the DER-encoded certificate (Base64Url).
###############################################################################

# 1. Configuration
KID="test-kid-2026"
TARGET_DIR="src/test/resources"
JWKS_FILE="$TARGET_DIR/azure-sample-keys.json"
TOKEN_FILE="$TARGET_DIR/azure-sample-token.txt"

# Ensure the directory exists
mkdir -p "$TARGET_DIR"

# 2. Generate Temporary Keys
# We use temporary names to ensure we don't overwrite anything important
openssl genrsa -out temp_private.pem 2048 2>/dev/null
openssl req -new -x509 -key temp_private.pem -out temp_cert.pem -days 10950 -subj "/CN=login.microsoftonline.test" 2>/dev/null

# 3. Helper function for Base64Url encoding that handles different OS flags
b64url() {
    # Try -w0 (Linux/GNU), if it fails, use -b0 (macOS/BSD), then remove newlines manually just in case
    (base64 -w0 2>/dev/null || base64 -b0 2>/dev/null || base64) | tr -d '\n=' | tr '+/' '-_'
}

# 4. Extract Components for JWKS
MOD=$(openssl rsa -in temp_private.pem -noout -modulus | cut -d'=' -f2 | xxd -r -p | b64url)
X5C=$(openssl x509 -in temp_cert.pem -outform DER | base64 | tr -d '\n')
X5T=$(openssl x509 -in temp_cert.pem -fingerprint -noout | cut -d'=' -f2 | sed 's/://g' | xxd -r -p | b64url)

# 5. Create the JWKS file
printf '{\n  "keys": [\n    {\n      "kty": "RSA",\n      "use": "sig",\n      "kid": "%s",\n      "x5t": "%s",\n      "n": "%s",\n      "e": "AQAB",\n      "x5c": ["%s"]\n    }\n  ]\n}\n' \
    "$KID" "$X5T" "$MOD" "$X5C" > "$JWKS_FILE"

# 6. Generate and Sign the Token
HEADER='{"alg":"RS256","typ":"JWT","kid":"'$KID'"}'
PAYLOAD='{"iss":"https://sts.windows.net/test-tenant/","sub":"junit-test","aud":"your-client-id","iat":1704067200,"exp":2524608000}'

H_B64=$(printf '%s' "$HEADER" | b64url)
P_B64=$(printf '%s' "$PAYLOAD" | b64url)

# IMPORTANT: Sign the "HEADER.PAYLOAD" string
# 'openssl dgst' can sometimes add metadata, so we pipe strictly the string
SIG=$(printf '%s.%s' "$H_B64" "$P_B64" | openssl dgst -sha256 -sign temp_private.pem -binary | b64url)

# Save the token as a single continuous line with NO trailing characters
printf "%s.%s.%s" "$H_B64" "$P_B64" "$SIG" | tr -d '[:space:]' > "$TOKEN_FILE"

# 7. Cleanup
rm temp_private.pem
rm temp_cert.pem

echo "Cleanup complete. Assets generated in $TARGET_DIR:"
echo " - $JWKS_FILE"
echo " - $TOKEN_FILE"
