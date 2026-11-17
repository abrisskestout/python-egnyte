#!/usr/bin/env bash
# Stop early, with instructions, if secrets that a PERSON has to provide are not in Key Vault yet.
#
#   KEY_VAULT_NAME=<vault> bash infra/scripts/require-secrets.sh egnyte-client-secret entra-client-secret
#
# Only checks that each secret exists; it never reads or prints a value.
set -euo pipefail

: "${KEY_VAULT_NAME:?KEY_VAULT_NAME is required}"
[ "$#" -gt 0 ] || { echo "usage: require-secrets.sh <secret name>..." >&2; exit 2; }

missing=()
for name in "$@"; do
  if ! az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "$name" --query id --output tsv >/dev/null 2>&1; then
    missing+=("$name")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "::error::Key Vault '$KEY_VAULT_NAME' is missing (or the pipeline cannot read): ${missing[*]}"
  cat <<EOF

Add each one once, then use "Re-run failed jobs" on this workflow run. In the portal:
  Key Vault '$KEY_VAULT_NAME' > Secrets > Generate/Import, with exactly the names above.
Or with the Azure CLI, from a file that holds only the secret:
  az keyvault secret set --vault-name $KEY_VAULT_NAME --name <name> --file <file> --output none
(Your own account needs the 'Key Vault Secrets Officer' role on the vault for that.)
EOF
  exit 1
fi
echo "All required secrets are present in '$KEY_VAULT_NAME'."
