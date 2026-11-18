"""Keeps main.bicep and the web app's settings code agreeing about the permission-test folder.

Pure Python: no bash, no Azure.  python -m unittest discover -s infra/tests -p "test_bicep_settings.py" -v
"""
import os
import re
import unittest

INFRA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(INFRA)


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fp:
        return fp.read()


class PermissionFolderTests(unittest.TestCase):
    def setUp(self):
        self.bicep = read("infra", "main.bicep")
        self.settings = read("web_app", "settings.py")

    def bicep_default(self):
        return re.search(r"param permissionTestFolder string = '([^']*)'", self.bicep).group(1)

    def code_default(self):
        return re.search(r'^DEFAULT_PERMISSION_FOLDER = "([^"]*)"', self.settings, re.MULTILINE).group(1)

    def test_the_template_and_the_app_have_the_same_default(self):
        self.assertEqual(self.bicep_default(), self.code_default())

    def test_the_default_is_the_requested_folder_with_forward_slashes(self):
        self.assertEqual(self.bicep_default(), "/Shared/Teams/IT/Infrastructure/Azure App Test")
        self.assertNotIn("\\", self.bicep_default())

    def test_the_template_passes_the_parameter_to_the_app_as_a_setting(self):
        self.assertIn("PERMISSION_TEST_FOLDER: permissionTestFolder", self.bicep)

    def test_the_setting_name_matches_what_the_app_reads(self):
        self.assertIn('"PERMISSION_TEST_FOLDER"', self.settings)


if __name__ == "__main__":
    unittest.main()
