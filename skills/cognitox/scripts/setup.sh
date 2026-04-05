#!/usr/bin/env bash
# Quick setup: create a user pool and client, print the IDs.
# Usage: bash scripts/setup.sh [pool-name] [client-name]

set -euo pipefail

ENDPOINT="${COGNITOX_URL:-http://localhost:9229}"
POOL_NAME="${1:-test-pool}"
CLIENT_NAME="${2:-test-client}"

# Check server
if ! curl -sf "$ENDPOINT/health" > /dev/null 2>&1; then
  echo "Error: cognitox not running at $ENDPOINT" >&2
  exit 1
fi

POOL=$(curl -sf "$ENDPOINT/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPool" \
  -d "{\"PoolName\": \"$POOL_NAME\"}")
POOL_ID=$(echo "$POOL" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)

CLIENT=$(curl -sf "$ENDPOINT/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPoolClient" \
  -d "{\"UserPoolId\": \"$POOL_ID\", \"ClientName\": \"$CLIENT_NAME\", \"ExplicitAuthFlows\": [\"ALLOW_USER_PASSWORD_AUTH\", \"ALLOW_REFRESH_TOKEN_AUTH\"]}")
CLIENT_ID=$(echo "$CLIENT" | grep -o '"ClientId":"[^"]*"' | cut -d'"' -f4)

echo "UserPoolId=$POOL_ID"
echo "ClientId=$CLIENT_ID"
