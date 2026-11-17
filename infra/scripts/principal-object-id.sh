#!/usr/bin/env bash
# Print the object ID of the identity the Azure CLI is logged in as, as `object_id=<guid>` (appended to
# $GITHUB_OUTPUT when that is set). The Bicep template needs it to grant the pipeline access to Key Vault.
#
# The ID is read from the `oid` claim of the CLI's own access token, so the pipeline needs no permission
# to read the directory. The token is masked and never printed.
set -euo pipefail

PYTHON="$(command -v python3 || command -v python)"

token="$(az account get-access-token --resource https://management.azure.com/ --query accessToken --output tsv)"
echo "::add-mask::$token"

oid="$(TOKEN="$token" "$PYTHON" - <<'PY'
import base64, json, os
payload = os.environ["TOKEN"].split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload)).get("oid", ""))
PY
)"

if ! [[ "$oid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "::error::Could not read an object id from the Azure access token."
  exit 1
fi
echo "object_id=$oid" >> "${GITHUB_OUTPUT:-/dev/stdout}"
