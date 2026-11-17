import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

import package
from helpers import KEY, SECRET


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.zip_path = os.path.join(cls.folder.name, "pkg.zip")
        _, cls.names = package.build(cls.zip_path)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_contains_the_app_the_vendored_library_and_the_license(self):
        for name in ("app.py", "wsgi.py", "settings.py", "identity.py", "egnyte_oauth.py", "token_store.py",
                     "egnyte_access.py", "requirements.txt", "templates/base.html", "templates/index.html",
                     "templates/folders.html", "templates/error.html", "static/app.css", ".deployment",
                     "egnyte/__init__.py", "egnyte/client.py", "egnyte/base.py", "egnyte/resources.py", "LICENSE.txt"):
            self.assertIn(name, self.names)

    def test_leaves_out_everything_that_does_not_belong(self):
        for name in self.names:
            self.assertNotIn("__pycache__", name)
            self.assertFalse(name.endswith((".pyc", ".tok", ".env", ".tmp")), name)
            self.assertFalse(name.startswith(("tests/", "egnyte/tests/", "dist/", ".egnyte-tokens")), name)
            self.assertNotIn("\\", name)
        self.assertNotIn("egnyte/__main__.py", self.names)
        self.assertNotIn("package.py", self.names)

    def test_the_zip_matches_the_list_and_has_no_duplicates(self):
        with zipfile.ZipFile(self.zip_path) as archive:
            self.assertEqual(sorted(archive.namelist()), sorted(self.names))
            self.assertEqual(len(set(archive.namelist())), len(archive.namelist()))
            self.assertIsNone(archive.testzip())

    def test_requirements_do_not_pull_the_old_pypi_egnyte(self):
        with zipfile.ZipFile(self.zip_path) as archive:
            lines = [line.split(">")[0].strip().lower() for line in archive.read("requirements.txt").decode().splitlines()
                     if line.strip()]
        self.assertNotIn("egnyte", lines)
        for needed in ("flask", "gunicorn", "requests", "cryptography", "azure-identity", "azure-keyvault-secrets"):
            self.assertIn(needed, lines)
        for test_only in ("nose", "coverage"):
            self.assertNotIn(test_only, lines)

    def test_the_deployment_file_turns_on_the_build(self):
        with zipfile.ZipFile(self.zip_path) as archive:
            self.assertIn(b"SCM_DO_BUILD_DURING_DEPLOYMENT=true", archive.read(".deployment"))

    def test_the_license_is_the_librarys(self):
        with zipfile.ZipFile(self.zip_path) as archive:
            with open(os.path.join(package.REPO, "LICENSE.txt"), "rb") as fp:
                self.assertEqual(archive.read("LICENSE.txt"), fp.read())

    def test_missing_pieces_stop_the_build(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(package.PackageError):
                package.collect(app_dir=empty, repo_dir=package.REPO)
            with self.assertRaises(package.PackageError):
                package.collect(app_dir=package.HERE, repo_dir=empty)

    def test_stray_files_next_to_the_app_are_not_picked_up(self):
        stray = os.path.join(package.HERE, "zz-stray.env")
        try:
            with open(stray, "w") as fp:
                fp.write("SECRET=1")
            self.assertNotIn("zz-stray.env", [name for _, name in package.collect()])
        finally:
            if os.path.exists(stray):
                os.remove(stray)


class UnpackedPackageRuns(unittest.TestCase):
    """Unpack the zip somewhere else and start the app from there, the way App Service will."""

    def test_the_unzipped_app_starts_and_uses_its_own_copy_of_egnyte(self):
        with tempfile.TemporaryDirectory() as work:
            site, tokens = os.path.join(work, "site"), os.path.join(work, "tokens")
            _, _ = package.build(os.path.join(work, "pkg.zip"))
            with zipfile.ZipFile(os.path.join(work, "pkg.zip")) as archive:
                archive.extractall(site)
            code = (
                "import json, os, sys\n"
                "sys.path.insert(0, os.getcwd())\n"                     # what gunicorn does with the app folder
                "import wsgi, egnyte, egnyte_access\n"
                "from tests_header import header\n"
                "client = wsgi.app.test_client()\n"
                "out = {'egnyte_file': egnyte.__file__, 'health': client.get('/healthz').status_code,\n"
                "       'anon': client.get('/').status_code}\n"
                "client.environ_base['HTTP_X_MS_CLIENT_PRINCIPAL'] = header\n"
                "page = client.get('/')\n"
                "out.update(signed_in=page.status_code, offers_connect='Connect to Egnyte' in page.get_data(as_text=True))\n"
                "print(json.dumps(out))\n"
            )
            from helpers import principal
            with open(os.path.join(site, "tests_header.py"), "w") as fp:
                fp.write(f"header = {principal('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a@example.com')!r}\n")
            env = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "TEMP", "TMP", "HOME")}
            env.update({"EGNYTE_DOMAIN": "stout", "EGNYTE_CLIENT_ID": "CLIENT123",
                        "EGNYTE_REDIRECT_URI": "https://webapp.example/egnyte/callback", "EGNYTE_CLIENT_SECRET": SECRET,
                        "FLASK_SECRET_KEY": "k" * 40, "TOKEN_ENCRYPTION_KEYS": KEY, "TOKEN_STORE_DIR": tokens})
            result = subprocess.run([sys.executable, "-c", code], cwd=site, env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            out = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(out["egnyte_file"].startswith(site), out["egnyte_file"])   # not from the repo, not from PyPI
        self.assertEqual((out["health"], out["anon"], out["signed_in"], out["offers_connect"]), (200, 401, 200, True))

    def test_starting_without_configuration_fails_with_a_clear_message(self):
        with tempfile.TemporaryDirectory() as work:
            package.build(os.path.join(work, "pkg.zip"))
            with zipfile.ZipFile(os.path.join(work, "pkg.zip")) as archive:
                archive.extractall(os.path.join(work, "site"))
            env = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "TEMP", "TMP", "HOME")}
            result = subprocess.run([sys.executable, "-c", "import sys, os; sys.path.insert(0, os.getcwd()); import wsgi"],
                                    cwd=os.path.join(work, "site"), env=env, capture_output=True, text=True, timeout=120)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ConfigError: EGNYTE_DOMAIN is not set.", result.stderr)


if __name__ == "__main__":
    unittest.main()
