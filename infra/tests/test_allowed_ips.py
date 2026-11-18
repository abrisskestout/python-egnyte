"""Guards infra/allowed-ips.json (the networks allowed to reach the web app) and the way main.bicep uses it.

Pure Python: no bash, no Azure.  python -m unittest discover -s infra/tests -p "test_allowed_ips.py" -v
"""
import ipaddress
import json
import os
import re
import unittest

INFRA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_PRIORITY = 2147483646          # App Service reserves 2147483647 for its implicit "deny all"


def load():
    with open(os.path.join(INFRA, "allowed-ips.json"), encoding="utf-8") as fp:
        return json.load(fp)


class AllowedIpsFileTests(unittest.TestCase):
    def setUp(self):
        self.entries = load()

    def test_there_are_entries_with_exactly_the_expected_fields(self):
        self.assertTrue(self.entries)
        for entry in self.entries:
            self.assertEqual(sorted(entry), ["ipAddress", "name", "priority"], entry)

    def test_every_entry_is_a_single_ipv4_address(self):
        for entry in self.entries:
            network = ipaddress.ip_network(entry["ipAddress"], strict=True)
            self.assertEqual((network.version, network.prefixlen), (4, 32), entry)

    def test_priorities_are_unique_integers_in_range(self):
        priorities = [e["priority"] for e in self.entries]
        for priority in priorities:
            self.assertIsInstance(priority, int)
            self.assertTrue(1 <= priority <= MAX_PRIORITY, priority)
        self.assertEqual(len(priorities), len(set(priorities)))

    def test_names_are_unique_and_plain(self):
        names = [e["name"] for e in self.entries]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertRegex(name, r"^[A-Za-z0-9 _-]{1,32}$")

    def test_no_address_is_listed_twice(self):
        addresses = [e["ipAddress"] for e in self.entries]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_the_file_is_kept_in_priority_order(self):
        priorities = [e["priority"] for e in self.entries]
        self.assertEqual(priorities, sorted(priorities))


class BicepUsesTheListTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(INFRA, "main.bicep"), encoding="utf-8") as fp:
            self.bicep = fp.read()

    def test_the_template_loads_this_file(self):
        self.assertIn("loadJsonContent('allowed-ips.json')", self.bicep)

    def test_listed_networks_are_allowed_and_everything_else_is_denied(self):
        self.assertRegex(self.bicep, r"ipSecurityRestrictions:\s*\[for rule in allowedIps")
        self.assertIn("action: 'Allow'", self.bicep)
        self.assertIn("ipSecurityRestrictionsDefaultAction: 'Deny'", self.bicep)

    def test_the_deployment_site_follows_the_same_list(self):
        self.assertIn("scmIpSecurityRestrictionsUseMain: true", self.bicep)

    def test_each_rule_takes_its_name_priority_and_address_from_the_file(self):
        for field in ("name: rule.name", "priority: rule.priority", "ipAddress: rule.ipAddress"):
            self.assertIn(field, self.bicep)

    def test_none_of_the_listed_addresses_is_hard_coded_in_the_template(self):
        for entry in load():
            address = entry["ipAddress"].split("/")[0]
            self.assertIsNone(re.search(rf"(?<![\d.]){re.escape(address)}(?![\d])", self.bicep), address)


if __name__ == "__main__":
    unittest.main()
