import unittest
from types import SimpleNamespace

import settings as cfg
from helpers import KEY, SECRET

ENV = {
    "EGNYTE_DOMAIN": "stout",
    "EGNYTE_CLIENT_ID": "CLIENT123",
    "EGNYTE_REDIRECT_URI": "https://webapp.example/egnyte/callback",
    "EGNYTE_CLIENT_SECRET": SECRET,
    "FLASK_SECRET_KEY": "k" * 40,
    "TOKEN_ENCRYPTION_KEYS": KEY,
}


class FakeVault:
    def __init__(self, **values):
        self.values, self.calls = values, []

    def get(self, name):
        self.calls.append(name)
        return self.values[name]


class SecretClient:
    """Stands in for azure.keyvault.secrets.SecretClient."""

    def __init__(self, values=None, error=None):
        self.values, self.error = values or {}, error

    def get_secret(self, name):
        if self.error:
            raise self.error
        return SimpleNamespace(value=self.values.get(name))


def load(**changes):
    env = dict(ENV)
    env.update(changes)
    env = {key: value for key, value in env.items() if value is not None}
    return cfg.load_settings(env)


class LoadingTests(unittest.TestCase):
    def test_loads_plain_settings_and_secrets_from_the_environment(self):
        s = load()
        self.assertEqual((s.domain, s.client_id, s.scope), ("stout.egnyte.com", "CLIENT123", "Egnyte.filesystem"))
        self.assertEqual(s.client_secret, SECRET)
        self.assertEqual(s.encryption_keys, (KEY,))
        self.assertFalse(s.on_azure)

    def test_several_encryption_keys_in_order(self):
        self.assertEqual(load(TOKEN_ENCRYPTION_KEYS=" a , b ,").encryption_keys, ("a", "b"))

    def test_secrets_never_appear_in_repr(self):
        text = repr(load())
        for secret in (SECRET, "k" * 40, KEY):
            self.assertNotIn(secret, text)

    def test_token_directory_defaults(self):
        self.assertEqual(load(WEBSITE_SITE_NAME="mysite").token_dir, "/home/data/egnyte-tokens")
        self.assertTrue(load().token_dir.endswith(".egnyte-tokens"))
        self.assertEqual(load(TOKEN_STORE_DIR="/data/t").token_dir, "/data/t")

    def test_scope_and_rate_limit_are_validated(self):
        self.assertEqual(load(EGNYTE_SCOPE="Egnyte.filesystem Egnyte.link").scope, "Egnyte.filesystem Egnyte.link")
        for bad in ({"EGNYTE_SCOPE": "Egnyte.everything"}, {"EGNYTE_MAX_RPS": "fast"}, {"EGNYTE_MAX_RPS": "1000"}):
            with self.subTest(bad=bad), self.assertRaises(cfg.ConfigError):
                load(**bad)
        self.assertEqual(load(EGNYTE_MAX_RPS="5").max_rps, 5.0)

    def test_bad_values_are_refused(self):
        bad = [{"EGNYTE_DOMAIN": "evil.example.com/x"}, {"EGNYTE_DOMAIN": None}, {"EGNYTE_CLIENT_ID": "a b"},
               {"EGNYTE_CLIENT_ID": None}, {"EGNYTE_REDIRECT_URI": "http://webapp.example/cb"},
               {"EGNYTE_REDIRECT_URI": None}, {"FLASK_SECRET_KEY": "short"}, {"TOKEN_ENCRYPTION_KEYS": " , "}]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(cfg.ConfigError):
                load(**change)


class DevUserTests(unittest.TestCase):
    def test_refused_on_app_service(self):
        with self.assertRaises(cfg.ConfigError):
            load(ALLOW_DEV_USER="1", WEBSITE_SITE_NAME="mysite")

    def test_allowed_locally_with_a_loopback_http_redirect(self):
        s = load(ALLOW_DEV_USER="1", EGNYTE_REDIRECT_URI="http://localhost:5000/egnyte/callback")
        self.assertTrue(s.allow_dev_user)

    def test_loopback_http_redirect_needs_dev_mode(self):
        with self.assertRaises(cfg.ConfigError):
            load(EGNYTE_REDIRECT_URI="http://localhost:5000/egnyte/callback")


class KeyVaultTests(unittest.TestCase):
    def test_unresolved_key_vault_reference_is_caught(self):
        reference = "@Microsoft.KeyVault(SecretUri=https://v.vault.azure.net/secrets/egnyte-client-secret/)"
        with self.assertRaises(cfg.ConfigError) as caught:
            load(EGNYTE_CLIENT_SECRET=reference)
        self.assertIn("unresolved Key Vault reference", str(caught.exception))
        self.assertIn("managed identity", str(caught.exception))
        self.assertNotIn(reference, str(caught.exception))

    def test_unresolved_reference_in_a_plain_setting_is_caught_too(self):
        with self.assertRaises(cfg.ConfigError):
            load(EGNYTE_CLIENT_ID="@Microsoft.KeyVault(VaultName=v;SecretName=s)")

    def test_secret_missing_everywhere_is_an_error(self):
        with self.assertRaises(cfg.ConfigError) as caught:
            load(EGNYTE_CLIENT_SECRET=None)
        self.assertIn("EGNYTE_CLIENT_SECRET", str(caught.exception))

    def test_missing_secrets_are_read_from_the_vault(self):
        vault = FakeVault(**{"egnyte-client-secret": f" {SECRET}\n", "flask-secret-key": "v" * 40,
                             "token-encryption-keys": KEY})
        env = {k: v for k, v in ENV.items() if k not in cfg.SECRET_NAMES}
        s = cfg.load_settings(env, vault=vault)
        self.assertEqual((s.client_secret, s.secret_key, s.encryption_keys), (SECRET, "v" * 40, (KEY,)))
        self.assertCountEqual(vault.calls, cfg.SECRET_NAMES.values())

    def test_environment_wins_and_the_vault_is_not_touched(self):
        vault = FakeVault()
        cfg.load_settings(dict(ENV), vault=vault)
        self.assertEqual(vault.calls, [])

    def test_vault_reader_returns_secrets(self):
        reader = cfg.VaultReader("https://myvault.vault.azure.net", client=SecretClient({"name": "value"}))
        self.assertEqual(reader.get("name"), "value")

    def test_vault_reader_hides_sdk_error_details(self):
        reader = cfg.VaultReader("https://myvault.vault.azure.net",
                                 client=SecretClient(error=RuntimeError("token=SECRETTOKEN403")))
        with self.assertRaises(cfg.ConfigError) as caught:
            reader.get("egnyte-client-secret")
        self.assertIn("RuntimeError", str(caught.exception))
        self.assertIn("Key Vault Secrets User", str(caught.exception))
        self.assertNotIn("SECRETTOKEN403", str(caught.exception))

    def test_empty_vault_secret_is_an_error(self):
        reader = cfg.VaultReader("https://myvault.vault.azure.net", client=SecretClient({"name": ""}))
        with self.assertRaises(cfg.ConfigError):
            reader.get("name")

    def test_vault_url_must_be_a_key_vault_over_https(self):
        for bad in ("http://myvault.vault.azure.net", "https://evil.example.com", "https://myvault.vault.azure.net.evil.com",
                    "https://myvault.vault.azure.net:8443", "myvault.vault.azure.net", ""):
            with self.subTest(url=bad), self.assertRaises(cfg.ConfigError):
                cfg.VaultReader(bad)

    def test_key_vault_url_setting_builds_a_reader(self):
        # No network: the reader is created lazily and only used if a secret is missing.
        s = load(KEY_VAULT_URL="https://myvault.vault.azure.net")
        self.assertEqual(s.client_secret, SECRET)


if __name__ == "__main__":
    unittest.main()
