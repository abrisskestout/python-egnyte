"""Configuration: ordinary settings come from App Settings, secrets come from Azure Key Vault.

Each secret is found in one of two ways:

1. An environment variable. On App Service, point the App Setting at the vault with a Key Vault
   reference, for example
       EGNYTE_CLIENT_SECRET=@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/egnyte-client-secret/)
   App Service resolves it with the app's managed identity before the app starts. This is the
   recommended route: the app never needs vault code or credentials of its own.
2. If the variable is not set and KEY_VAULT_URL is, the app reads the secret from the vault itself
   with DefaultAzureCredential (managed identity on Azure, `az login` on your PC).

Nothing here ever prints a secret.
"""
import os
import re
import urllib.parse
from dataclasses import dataclass, field

import egnyte_oauth

KV_REFERENCE_PREFIX = "@Microsoft.KeyVault("
VAULT_HOST_SUFFIXES = (".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net",
                       ".vault.microsoftazure.de", ".managedhsm.azure.net")
LOCAL_TOKEN_DIR = ".egnyte-tokens"   # token files, only when running on a PC without Cosmos DB
COSMOS_HOST_SUFFIXES = (".documents.azure.com", ".documents.azure.cn", ".documents.azure.us",
                        ".documents.microsoftazure.de")
# Where the tokens live in Cosmos DB. infra/main.bicep carries the same defaults;
# infra/tests/test_cosmos_infra.py keeps the two in step.
DEFAULT_COSMOS_DATABASE = "egnyte-auth"
DEFAULT_COSMOS_CONTAINER = "tokens"

# environment variable -> name of the secret in the vault
SECRET_NAMES = {
    "EGNYTE_CLIENT_SECRET": "egnyte-client-secret",
    "FLASK_SECRET_KEY": "flask-secret-key",
    "TOKEN_ENCRYPTION_KEYS": "token-encryption-keys",
}


# The Egnyte folder the Permission test page works in (the PERMISSION_TEST_FOLDER app setting overrides it).
# infra/main.bicep carries the same default; infra/tests/test_bicep_settings.py keeps the two in step.
DEFAULT_PERMISSION_FOLDER = "/Shared/Teams/IT/Infrastructure/Azure App Test"
MAX_FOLDER_LENGTH = 512


class ConfigError(Exception):
    """The app is misconfigured. The message names the setting and never contains a secret."""


def normalize_folder(value):
    """An Egnyte folder path from configuration: either slash style, with or without the leading or trailing slash.

    '\\Shared\\Teams\\IT' and 'Shared/Teams/IT/' both become '/Shared/Teams/IT'. Raises ConfigError for anything that
    isn't a plain path at least two levels deep (so never the root, and never '..')."""
    text = (value or "").strip().replace("\\", "/")
    if len(text) > MAX_FOLDER_LENGTH or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ConfigError("PERMISSION_TEST_FOLDER is too long or contains control characters.")
    path = "/" + text.strip("/")
    parts = path.split("/")[1:]
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise ConfigError("PERMISSION_TEST_FOLDER must be an Egnyte folder at least two levels deep, "
                          "such as /Shared/Teams/IT, with no '..', '.' or empty parts.")
    return path


def normalize_cosmos_endpoint(value):
    """The Cosmos DB account endpoint from configuration, as https://<account>.documents.azure.com:443/.

    Only a plain https address of a Cosmos DB account is accepted: no credentials in the URL (a connection string
    or key has no place here; the app signs in with its managed identity), no other port, path or query."""
    try:
        parts = urllib.parse.urlsplit((value or "").strip())
        port = parts.port
    except ValueError:
        port = -1
        parts = None
    host = ((parts.hostname if parts else "") or "").lower()
    if (parts is None or parts.scheme != "https" or not host.endswith(COSMOS_HOST_SUFFIXES) or port not in (None, 443)
            or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise ConfigError("COSMOS_ENDPOINT must look like https://<account name>.documents.azure.com:443/ "
                          "(an address only: no key and no connection string).")
    return f"https://{host}:443/"


def _cosmos_name(environ, name, default):
    value = _plain(environ, name, required=False) or default
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", value):
        raise ConfigError(f"{name} may only contain letters, digits, '.', '_' and '-'.")
    return value


class VaultReader:
    """Reads secrets straight from Key Vault. The Azure SDK is imported only when it is first needed."""

    def __init__(self, vault_url, client=None):
        parts = urllib.parse.urlsplit(vault_url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not host.endswith(VAULT_HOST_SUFFIXES) or parts.port not in (None, 443):
            raise ConfigError("KEY_VAULT_URL must look like https://<vault name>.vault.azure.net")
        self.vault_url = f"https://{host}"
        self._client = client

    def get(self, name):
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            self._client = SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())
        try:
            value = self._client.get_secret(name).value
        except Exception as e:  # the SDK raises many types; none of their messages are shown
            raise ConfigError(f"Could not read the Key Vault secret {name!r} ({type(e).__name__}). Check that the "
                              "identity running the app has the 'Key Vault Secrets User' role on the vault.") from None
        if not value:
            raise ConfigError(f"The Key Vault secret {name!r} is empty.")
        return value


@dataclass(frozen=True)
class Settings:
    domain: str                      # e.g. stout.egnyte.com
    client_id: str                   # the Egnyte API key; not secret enough to need the vault
    redirect_uri: str
    scope: str
    client_secret: str = field(repr=False)
    secret_key: str = field(repr=False)
    encryption_keys: tuple = field(repr=False)
    token_dir: str = LOCAL_TOKEN_DIR
    max_rps: float = 2.0
    allow_dev_user: bool = False
    on_azure: bool = False
    permission_folder: str = DEFAULT_PERMISSION_FOLDER
    cosmos_endpoint: str = ""        # empty: tokens go in files under token_dir (never allowed on App Service)
    cosmos_database: str = DEFAULT_COSMOS_DATABASE
    cosmos_container: str = DEFAULT_COSMOS_CONTAINER


def _plain(environ, name, required=True):
    value = (environ.get(name) or "").strip()
    if value.startswith(KV_REFERENCE_PREFIX):
        raise ConfigError(f"{name} still holds an unresolved Key Vault reference. Enable the app's managed identity "
                          "and give it the 'Key Vault Secrets User' role on the vault, then restart the app.")
    if required and not value:
        raise ConfigError(f"{name} is not set.")
    return value


def read_secret(environ, name, vault):
    """The secret `name`: from the environment if set, else from the vault. Never returns a Key Vault reference."""
    if (environ.get(name) or "").strip():
        return _plain(environ, name)
    if vault is None:
        raise ConfigError(f"{name} is not set, and KEY_VAULT_URL is not set, so there is nowhere to read it from.")
    return vault.get(SECRET_NAMES[name]).strip()


def _number(environ, name, default, low, high):
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number.") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}.")
    return value


def load_settings(environ=None, vault=None):
    """Build Settings from the environment (App Settings). `vault` is injectable for tests."""
    environ = os.environ if environ is None else environ
    on_azure = bool(environ.get("WEBSITE_SITE_NAME"))
    allow_dev_user = (environ.get("ALLOW_DEV_USER") or "").strip() == "1"
    if allow_dev_user and on_azure:
        raise ConfigError("ALLOW_DEV_USER=1 would let anyone pick their own identity; it is refused on App Service.")

    vault_url = (environ.get("KEY_VAULT_URL") or "").strip()
    if vault is None and vault_url:
        vault = VaultReader(vault_url)

    try:
        domain = egnyte_oauth.normalize_domain(_plain(environ, "EGNYTE_DOMAIN"))
        redirect_uri = egnyte_oauth.validate_redirect_uri(
            _plain(environ, "EGNYTE_REDIRECT_URI"), allow_loopback_http=allow_dev_user)
        scope = egnyte_oauth.resolve_scope(_plain(environ, "EGNYTE_SCOPE", required=False))
    except ValueError as e:
        raise ConfigError(str(e)) from None
    client_id = _plain(environ, "EGNYTE_CLIENT_ID")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", client_id):
        raise ConfigError("EGNYTE_CLIENT_ID contains unexpected characters.")

    client_secret = read_secret(environ, "EGNYTE_CLIENT_SECRET", vault)
    secret_key = read_secret(environ, "FLASK_SECRET_KEY", vault)
    if len(secret_key) < 32:
        raise ConfigError("FLASK_SECRET_KEY must be at least 32 characters.")
    keys = tuple(k.strip() for k in read_secret(environ, "TOKEN_ENCRYPTION_KEYS", vault).split(",") if k.strip())
    if not keys:
        raise ConfigError("TOKEN_ENCRYPTION_KEYS must hold at least one key.")

    token_dir = (environ.get("TOKEN_STORE_DIR") or "").strip() or os.path.join(os.getcwd(), LOCAL_TOKEN_DIR)
    permission_folder = normalize_folder(_plain(environ, "PERMISSION_TEST_FOLDER", required=False)
                                         or DEFAULT_PERMISSION_FOLDER)

    cosmos_endpoint = _plain(environ, "COSMOS_ENDPOINT", required=False)
    if cosmos_endpoint:
        cosmos_endpoint = normalize_cosmos_endpoint(cosmos_endpoint)
    elif on_azure:
        raise ConfigError("COSMOS_ENDPOINT is not set. On App Service the Egnyte tokens are kept in Cosmos DB "
                          "(created by infra/main.bicep, which also sets this app setting).")
    return Settings(
        domain=domain, client_id=client_id, redirect_uri=redirect_uri, scope=scope,
        client_secret=client_secret, secret_key=secret_key, encryption_keys=keys,
        token_dir=token_dir, max_rps=_number(environ, "EGNYTE_MAX_RPS", 2.0, 0.1, 20.0),
        allow_dev_user=allow_dev_user, on_azure=on_azure, permission_folder=permission_folder,
        cosmos_endpoint=cosmos_endpoint,
        cosmos_database=_cosmos_name(environ, "COSMOS_DATABASE", DEFAULT_COSMOS_DATABASE),
        cosmos_container=_cosmos_name(environ, "COSMOS_CONTAINER", DEFAULT_COSMOS_CONTAINER))
