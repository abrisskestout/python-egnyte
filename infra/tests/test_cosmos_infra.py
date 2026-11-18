"""Guards for the Cosmos DB token store: the Bicep and the web app must agree, and nothing may use a key.

Pure Python: no bash, no Azure.  python -m unittest discover -s infra/tests -p "test_cosmos_infra.py" -v
"""
import glob
import ipaddress
import json
import os
import re
import unittest

INFRA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(INFRA)

# Anything that would let a key or connection string into the picture.
FORBIDDEN = ("listKeys", "listConnectionStrings", "primaryMasterKey", "secondaryMasterKey", "primaryReadonlyMasterKey",
             "AccountKey", "AccountEndpoint=", "from_connection_string", "COSMOS_KEY", "COSMOS_CONNECTION")
# Address ranges the Cosmos DB firewall can't enforce (Microsoft Learn: Configure IP firewall).
UNENFORCEABLE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")]


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fp:
        return fp.read()


def sources():
    """Every Bicep file and every application source file (not the tests, which name the forbidden things)."""
    paths = glob.glob(os.path.join(INFRA, "**", "*.bicep"), recursive=True)
    paths += glob.glob(os.path.join(REPO, "web_app", "*.py")) + glob.glob(os.path.join(REPO, "web_app", "templates", "*"))
    return paths


class NoKeysTests(unittest.TestCase):
    def test_there_is_something_to_scan(self):
        names = [os.path.basename(p) for p in sources()]
        for expected in ("main.bicep", "cosmos-db.bicep", "cosmos-data-access.bicep", "token_store.py", "settings.py"):
            self.assertIn(expected, names)

    def test_no_key_or_connection_string_anywhere_in_the_template_or_the_app(self):
        for path in sources():
            with open(path, encoding="utf-8") as fp:
                text = fp.read()
            for word in FORBIDDEN:
                self.assertNotIn(word, text, f"{word!r} found in {os.path.relpath(path, REPO)}")

    def test_the_account_has_local_authentication_switched_off(self):
        bicep = read("infra", "modules", "cosmos-db.bicep")
        self.assertRegex(bicep, r"disableLocalAuth:\s*true\b")
        self.assertRegex(bicep, r"disableKeyBasedMetadataWriteAccess:\s*true\b")
        self.assertNotRegex(bicep, r"disableLocalAuth:\s*false")


class DataAccessTests(unittest.TestCase):
    def setUp(self):
        self.access = read("infra", "modules", "cosmos-data-access.bicep")
        self.main = read("infra", "main.bicep")

    def test_the_role_is_the_built_in_data_contributor(self):
        # Microsoft Learn, "Data plane security reference": Built-in Data Contributor is ...0002 (Data Reader is ...0001).
        self.assertIn("param roleDefinitionGuid string = '00000000-0000-0000-0000-000000000002'", self.access)

    def test_it_is_scoped_to_the_one_container_not_the_account(self):
        self.assertIn("scope: '${account.id}/dbs/${databaseName}/colls/${containerName}'", self.access)

    def test_the_web_apps_managed_identity_gets_it(self):
        self.assertRegex(self.main, r"module cosmosAccess 'modules/cosmos-data-access\.bicep'")
        self.assertIn("principalId: webApp.identity.principalId", self.main)
        self.assertRegex(self.main, r"identity:\s*\{\s*type:\s*'SystemAssigned'")

    def test_the_assignment_name_is_a_deterministic_guid(self):
        self.assertRegex(self.access, r"name:\s*guid\(account\.id, databaseName, containerName, principalId, roleDefinitionGuid\)")

    def test_the_app_settings_wait_for_the_role(self):
        settings_block = self.main[self.main.index("resource appSettings"):self.main.index("resource logs")]
        self.assertIn("cosmosAccess", settings_block)


class SettingsAgreementTests(unittest.TestCase):
    def setUp(self):
        self.main = read("infra", "main.bicep")
        self.settings = read("web_app", "settings.py")

    def bicep_default(self, name):
        return re.search(rf"param {name} string = '([^']*)'", self.main).group(1)

    def code_default(self, name):
        return re.search(rf'^{name} = "([^"]*)"', self.settings, re.MULTILINE).group(1)

    def test_database_and_container_defaults_match_the_app(self):
        self.assertEqual(self.bicep_default("cosmosDatabaseName"), self.code_default("DEFAULT_COSMOS_DATABASE"))
        self.assertEqual(self.bicep_default("cosmosContainerName"), self.code_default("DEFAULT_COSMOS_CONTAINER"))

    def test_the_template_sets_every_cosmos_setting_the_app_reads(self):
        for setting in ("COSMOS_ENDPOINT", "COSMOS_DATABASE", "COSMOS_CONTAINER"):
            self.assertIn(f'"{setting}"', self.settings, f"{setting} is not read by settings.py")
        self.assertIn("COSMOS_ENDPOINT: cosmos.outputs.endpoint", self.main)
        self.assertIn("COSMOS_DATABASE: cosmos.outputs.databaseName", self.main)
        self.assertIn("COSMOS_CONTAINER: cosmos.outputs.containerName", self.main)

    def test_no_connection_string_style_setting_is_defined(self):
        self.assertNotRegex(self.main, r"COSMOS_[A-Z_]*(KEY|CONNECTION|SECRET)")

    def test_the_partition_key_is_the_document_id_the_store_uses(self):
        # The store reads and deletes with partition_key == id, so the container must be partitioned on /id.
        self.assertIn("param partitionKeyPath string = '/id'", read("infra", "modules", "cosmos-db.bicep"))
        self.assertNotIn("partitionKeyPath:", self.main)       # main must not override it


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.main = read("infra", "main.bicep")
        with open(os.path.join(INFRA, "allowed-ips.json"), encoding="utf-8") as fp:
            self.allowed = json.load(fp)

    def test_the_firewall_gets_the_allow_list_and_the_web_apps_own_outbound_addresses(self):
        self.assertIn("allowedIpAddresses: cosmosAllowedIps", self.main)
        self.assertIn("map(allowedIps, rule => replace(rule.ipAddress, '/32', ''))", self.main)
        # Without these the web app would be locked out of its own database.
        self.assertIn("webApp.properties.outboundIpAddresses", self.main)
        self.assertIn("webApp.properties.possibleOutboundIpAddresses", self.main)

    def test_the_web_app_itself_does_not_depend_on_cosmos(self):
        # The firewall needs the web app's outbound addresses and the app settings need the Cosmos endpoint, so the
        # web app resource must stay free of Cosmos (otherwise the template has a dependency cycle).
        block = self.main[self.main.index("resource webApp"):self.main.index("resource appCanReadSecrets")]
        self.assertNotIn("cosmos", block.lower())

    def test_every_allowed_network_is_one_cosmos_can_enforce(self):
        for rule in self.allowed:
            network = ipaddress.ip_network(rule["ipAddress"], strict=False)
            self.assertEqual(network.version, 4, rule["name"])
            for blocked in UNENFORCEABLE:
                self.assertFalse(network.subnet_of(blocked), f"{rule['name']} is in a range Cosmos DB can't enforce")

    def test_single_addresses_become_plain_addresses(self):
        for rule in self.allowed:
            if rule["ipAddress"].endswith("/32"):
                self.assertEqual(rule["ipAddress"].replace("/32", ""), str(ipaddress.ip_interface(rule["ipAddress"]).ip))


if __name__ == "__main__":
    unittest.main()
