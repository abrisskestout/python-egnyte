#!/usr/bin/env bash
# Create the two Key Vault secrets nobody should ever have to type: the session-signing key and the
# token-encryption key. Run it once after deploying infra/main.bicep (needs `az login`, and the
# "Key Vault Secrets Officer" role on the vault for your account).
#
#   KEY_VAULT_NAME=<vault> bash infra/scripts/ensure-generated-secrets.sh
#
# An existing secret is NEVER replaced: a new token-encryption key would make every stored Egnyte token
# unreadable, so every user would have to connect again. A value is never printed or put on a command line.
#
# Role assignments can take a few minutes to take effect, so reading or writing is retried
# (MAX_ATTEMPTS times, RETRY_DELAY seconds apart).
set -euo pipefail

: "${KEY_VAULT_NAME:?KEY_VAULT_NAME is required}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-12}"
RETRY_DELAY="${RETRY_DELAY:-15}"
PYTHON="$(command -v python3 || command -v python)"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

generate_flask_secret_key() {
  "$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(48))'
}

# A Fernet key: 32 random bytes, URL-safe base64.
generate_token_encryption_key() {
  "$PYTHON" -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
}

ensure_secret() {
  local name="$1" generator="$2" attempt
  for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    if az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "$name" --query id --output tsv >/dev/null 2>"$WORK/error"; then
      echo "Secret '$name' already exists; leaving it as it is."
      return 0
    fi
    if grep -q "SecretNotFound" "$WORK/error"; then
      "$generator" | tr -d '\r\n' > "$WORK/value"   # no line ending of any kind may end up in the secret
      # --file keeps the value off the command line.
      if az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "$name" --file "$WORK/value" --output none 2>"$WORK/error"; then
        rm -f "$WORK/value"
        echo "Created secret '$name'."
        return 0
      fi
    fi
    echo "Attempt $attempt of $MAX_ATTEMPTS for '$name' did not work yet (new role assignments can take a few minutes); waiting ${RETRY_DELAY}s."
    sleep "$RETRY_DELAY"
  done
  echo "ERROR: Could not read or create the Key Vault secret '$name'. Last error: $(head -c 300 "$WORK/error")" >&2
  return 1
}

ensure_secret flask-secret-key generate_flask_secret_key
ensure_secret token-encryption-keys generate_token_encryption_key
