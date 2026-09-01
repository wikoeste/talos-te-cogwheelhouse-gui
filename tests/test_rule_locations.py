import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from liono.common import rulesearch, settings, snortreplay


class RuleLocationTests(unittest.TestCase):
    def test_configured_locations_include_var_tmp_aliases(self):
        self.assertEqual(settings.rulesDir, "/var/tmp/snort-rules/")
        self.assertEqual(
            settings.rulesDirs,
            ("/var/tmp/snort-rules/", "/private/var/tmp/snort-rules/"),
        )

    def test_default_rule_search_uses_every_configured_location(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory, "var", "snort-rules")
            second = Path(directory, "private-var", "snort-rules")
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            first.joinpath("first.rules").write_text(
                "alert tcp any any -> any any (sid:1001;)\n", encoding="utf-8"
            )
            second.joinpath("second.rules").write_text(
                "alert tcp any any -> any any (sid:1002;)\n", encoding="utf-8"
            )
            with patch.object(settings, "rulesDirs", (str(first), str(second))):
                matches = rulesearch.find_signatures(["1001", "1002"])
        self.assertEqual([match["sid"] for match in matches], ["1001", "1002"])

    def test_snort_command_uses_canonical_var_tmp_location(self):
        with patch.object(settings, "rulesDir", "/var/tmp/snort-rules/"):
            command = snortreplay.build_snort_command("sec", pcap="sample.pcap")
        rule_path_index = command.index("--rule-path") + 1
        self.assertEqual(command[rule_path_index], "/var/tmp/snort-rules")


if __name__ == "__main__":
    unittest.main()
