"""Tests for egnyte_credentials.py: the credential store and the locked-down config file."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock

from helpers import FakeBackend, acl_principals, whoami

import egnyte_credentials as creds


def keyring_available():
    try:
        import keyring  # noqa: F401
    except ImportError:
        return False
    return True


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="creds-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def assert_only_current_user(self, path):
        if os.name == "nt":
            self.assertEqual([p.casefold() for p in acl_principals(path)], [whoami().casefold()], path)
        else:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0, f"{path} is accessible to others")


class CredentialStoreTests(unittest.TestCase):
    def test_reference_round_trip(self):
        self.assertEqual(creds.split_ref(creds.token_ref("acme.egnyte.com")), ("python-egnyte", "acme.egnyte.com"))

    def test_bad_references_are_rejected(self):
        for ref in (None, "", "token", "file:python-egnyte:x", "keyring:", "keyring:svc", "keyring:svc:", 5):
            with self.subTest(ref=ref), self.assertRaises(creds.CredentialStoreError):
                creds.split_ref(ref)

    def test_store_load_delete(self):
        backend = FakeBackend()
        ref = creds.store_token("acme.egnyte.com", "tok-1", backend)
        self.assertEqual(creds.load_token(ref, backend), "tok-1")
        creds.delete_token(ref, backend)
        with self.assertRaises(creds.CredentialStoreError):
            creds.load_token(ref, backend)

    def test_backend_errors_never_leak_the_token(self):
        class Broken(FakeBackend):
            def set_password(self, service, name, password):
                raise RuntimeError(f"cannot store {password}")

        with self.assertRaises(creds.CredentialStoreError) as caught:
            creds.store_token("acme.egnyte.com", "tok-SECRET-9", Broken())
        self.assertNotIn("tok-SECRET-9", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_missing_keyring_package_gives_install_hint(self):
        with mock.patch.dict(sys.modules, {"keyring": None}):
            with self.assertRaises(creds.CredentialStoreError) as caught:
                creds.default_backend()
        self.assertIn("pip install keyring", str(caught.exception))

    def test_keyring_without_a_real_store_is_refused(self):
        class FailKeyring:
            pass

        fail_module = types.ModuleType("keyring.backends.fail")
        fail_module.Keyring = FailKeyring
        backends_module = types.ModuleType("keyring.backends")
        backends_module.fail = fail_module
        keyring_module = types.ModuleType("keyring")
        keyring_module.backends = backends_module
        keyring_module.get_keyring = lambda: FailKeyring()
        fakes = {"keyring": keyring_module, "keyring.backends": backends_module,
                 "keyring.backends.fail": fail_module}
        with mock.patch.dict(sys.modules, fakes):
            with self.assertRaises(creds.CredentialStoreError) as caught:
                creds.default_backend()
        self.assertIn("no usable OS credential store", str(caught.exception))

    @unittest.skipUnless(os.name == "nt" and keyring_available(), "needs Windows and the keyring package")
    def test_real_windows_credential_manager_round_trip(self):
        domain = f"unit-test-{uuid.uuid4().hex[:8]}.invalid"
        ref = creds.store_token(domain, "tok-real-1234")
        self.addCleanup(creds.delete_token, ref)
        self.assertEqual(creds.load_token(ref), "tok-real-1234")
        import keyring
        self.assertEqual(keyring.get_password("python-egnyte", domain), "tok-real-1234")


class WritePrivateJsonTests(TempDirCase):
    def path(self, *parts):
        return os.path.join(self.tmp, "cfg", *parts)

    def leftovers(self):
        return [n for n in os.listdir(os.path.dirname(self.path("config.json"))) if n.endswith(".tmp")]

    def test_writes_json_and_leaves_no_temp_file(self):
        creds.write_private_json(self.path("config.json"), {"domain": "acme.egnyte.com", "n": 1})
        with open(self.path("config.json"), encoding="utf-8") as fp:
            self.assertEqual(json.load(fp), {"domain": "acme.egnyte.com", "n": 1})
        self.assertEqual(self.leftovers(), [])

    def test_file_and_folder_are_limited_to_the_current_user(self):
        creds.write_private_json(self.path("config.json"), {"access_token": "tok"}, restrict=True)
        self.assert_only_current_user(self.path())
        self.assert_only_current_user(self.path("config.json"))

    def test_rewriting_keeps_the_file_private(self):
        creds.write_private_json(self.path("config.json"), {"v": 1})
        creds.write_private_json(self.path("config.json"), {"v": 2})
        self.assert_only_current_user(self.path("config.json"))
        with open(self.path("config.json"), encoding="utf-8") as fp:
            self.assertEqual(json.load(fp), {"v": 2})

    def test_interrupted_write_keeps_the_old_file_and_cleans_up(self):
        creds.write_private_json(self.path("config.json"), {"v": "old"})
        with mock.patch.object(os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                creds.write_private_json(self.path("config.json"), {"v": "new"})
        with open(self.path("config.json"), encoding="utf-8") as fp:
            self.assertEqual(json.load(fp), {"v": "old"})
        self.assertEqual(self.leftovers(), [])

    def test_failure_to_restrict_writes_nothing(self):
        creds.write_private_json(self.path("config.json"), {"v": "old"})
        real = creds.restrict_to_current_user

        def fail_for_files(path, directory):
            if not directory:
                raise creds.CredentialStoreError("nope")
            real(path, directory)

        with mock.patch.object(creds, "restrict_to_current_user", side_effect=fail_for_files):
            with self.assertRaises(creds.CredentialStoreError):
                creds.write_private_json(self.path("config.json"), {"v": "new"}, restrict=True)
        with open(self.path("config.json"), encoding="utf-8") as fp:
            self.assertEqual(json.load(fp), {"v": "old"})
        self.assertEqual(self.leftovers(), [])

    def test_json_serialisation_failure_cleans_up(self):
        with self.assertRaises(TypeError):
            creds.write_private_json(self.path("config.json"), {"bad": object()})
        self.assertFalse(os.path.exists(self.path("config.json")))
        self.assertEqual(self.leftovers(), [])

    def make_dir_link(self, link, target):
        if os.name == "nt":  # a junction needs no special privilege
            result = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True)
            if result.returncode != 0:
                self.skipTest("could not create a junction")
        else:
            os.symlink(target, link, target_is_directory=True)

    def test_refuses_a_linked_folder(self):
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        link = os.path.join(self.tmp, "link")
        self.make_dir_link(link, real)
        with self.assertRaises(creds.CredentialStoreError):
            creds.write_private_json(os.path.join(link, "config.json"), {"v": 1})
        self.assertEqual(os.listdir(real), [])

    def test_refuses_a_linked_file(self):
        os.makedirs(self.path())
        victim = os.path.join(self.tmp, "victim.txt")
        with open(victim, "w") as fp:
            fp.write("keep me")
        try:
            os.symlink(victim, self.path("config.json"))
        except OSError:
            self.skipTest("symbolic links are not available to this user")
        with self.assertRaises(creds.CredentialStoreError):
            creds.write_private_json(self.path("config.json"), {"v": 1})
        with open(victim) as fp:
            self.assertEqual(fp.read(), "keep me")


class RejectLinkTests(unittest.TestCase):
    """reject_link() decides from lstat() alone, so a fake result covers cases a user can't create."""

    def fake_lstat(self, mode, attributes=0):
        return mock.patch.object(os, "lstat", return_value=types.SimpleNamespace(
            st_mode=mode, st_file_attributes=attributes))

    def test_symbolic_link_is_refused(self):
        with self.fake_lstat(stat.S_IFLNK), self.assertRaises(creds.CredentialStoreError):
            creds.reject_link("config.json")

    def test_reparse_point_is_refused(self):
        with self.fake_lstat(stat.S_IFREG, stat.FILE_ATTRIBUTE_REPARSE_POINT), \
                self.assertRaises(creds.CredentialStoreError):
            creds.reject_link("config.json")

    def test_ordinary_file_and_missing_file_pass(self):
        with self.fake_lstat(stat.S_IFREG):
            creds.reject_link("config.json")
        with mock.patch.object(os, "lstat", side_effect=FileNotFoundError):
            creds.reject_link("missing.json")


class TestAppIntegrationTests(TempDirCase):
    """egnyte_test_app.py must be able to use what egnyte_oauth_login.py stored."""

    def setUp(self):
        super().setUp()
        import egnyte_test_app
        self.app = egnyte_test_app
        self.config = os.path.join(self.tmp, "config.json")
        with open(self.config, "w", encoding="utf-8") as fp:
            json.dump({"domain": "acme.egnyte.com", "access_token_ref": creds.token_ref("acme.egnyte.com")}, fp)
        self.backend = FakeBackend()
        self.backend.set_password("python-egnyte", "acme.egnyte.com", "tok-from-store")
        for name in self.app.ENV_VARS.values():
            self.addCleanup(os.environ.pop, name, None)
            os.environ.pop(name, None)

    def test_token_is_loaded_from_the_credential_store(self):
        with mock.patch.object(creds, "default_backend", return_value=self.backend):
            config = self.app.load_config(self.config)
        self.assertEqual(config["access_token"], "tok-from-store")

    def test_an_explicit_token_wins_and_the_store_is_not_touched(self):
        with mock.patch.dict(os.environ, {"EGNYTE_ACCESS_TOKEN": "tok-from-env"}), \
                mock.patch.object(creds, "default_backend", side_effect=AssertionError("store used")):
            config = self.app.load_config(self.config)
        self.assertEqual(config["access_token"], "tok-from-env")

    def test_missing_stored_token_is_a_setup_error_not_a_crash(self):
        with mock.patch.object(creds, "default_backend", return_value=FakeBackend()), \
                mock.patch("builtins.print") as shown:
            code = self.app.main(["--config", self.config])
        self.assertEqual(code, 2)
        self.assertIn("Could not read the saved token", " ".join(str(c.args[0]) for c in shown.call_args_list))


if __name__ == "__main__":
    unittest.main()
