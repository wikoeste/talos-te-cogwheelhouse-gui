import csv
import tempfile
import unittest
from pathlib import Path

from liono.common import sicategories


SAMPLE_STORAGE = """
<table>
  <tbody>
    <tr><th>SI Category</th><th>Feeds Mapping Category</th><th>Expiration Time</th><th>Description</th></tr>
    <tr><td>bots</td><td>bots</td><td>1 day</td><td>Botnet member</td></tr>
    <tr><td>cnc</td><td>bots</td><td>30 days</td><td>Controller</td></tr>
    <tr><td>other</td><td>unk_other</td><td></td><td></td></tr>
  </tbody>
</table>
"""


class SICategoryTests(unittest.TestCase):
    def test_duplicate_mappings_use_first_expiration_time(self):
        result = sicategories._parse_expirations(SAMPLE_STORAGE)

        self.assertEqual(result["bots"], "1 day")
        self.assertEqual(result["unk_other"], "Unknown")

    def test_feed_rows_receive_expiration_or_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "feeds.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=[
                        "wbrs_description", "score", "threat_mnemonic",
                        "threat_description",
                    ],
                )
                writer.writeheader()
                writer.writerow({
                    "wbrs_description": "Bot feed", "score": "-5",
                    "threat_mnemonic": "bots", "threat_description": "Botnets",
                })
                writer.writerow({
                    "wbrs_description": "Unknown feed", "score": "0",
                    "threat_mnemonic": "NULL", "threat_description": "",
                })

            rows = sicategories.load_feed_rows(csv_path, {"bots": "1 day"})

        self.assertEqual(rows[0]["expiration_time"], "1 day")
        self.assertEqual(rows[1]["expiration_time"], "Unknown")

    def test_missing_expected_table_is_rejected(self):
        with self.assertRaisesRegex(
            sicategories.SICategoryFetchError, "expected SI Category",
        ):
            sicategories._parse_expirations("<table><tr><th>Other</th></tr></table>")


if __name__ == "__main__":
    unittest.main()
