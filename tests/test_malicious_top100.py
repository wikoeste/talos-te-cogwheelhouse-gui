import unittest

from liono.common.malicious_top100 import (
    Source,
    parse_ipsum,
    parse_threatfox,
    rank_store,
    valid_public_ip,
    valid_url,
)


class MaliciousTop100Tests(unittest.TestCase):
    def test_ip_validation(self):
        self.assertEqual(valid_public_ip("8.8.8.8"), "8.8.8.8")
        self.assertIsNone(valid_public_ip("127.0.0.1"))
        self.assertIsNone(valid_public_ip("10.0.0.1"))

    def test_url_validation(self):
        self.assertEqual(valid_url("https://example.com/a"), "https://example.com/a")
        self.assertIsNone(valid_url("file:///etc/passwd"))
        self.assertIsNone(valid_url("http://localhost/admin"))

    def test_ipsum_confidence(self):
        source = Source("IPsum", "https://example.com", ("ips",), "ipsum", 72, "https://example.com")
        store = {"urls": {}, "ips": {}, "hashes": {}}
        self.assertEqual(parse_ipsum("8.8.8.8 5\n", source, store), 1)
        self.assertEqual(store["ips"]["8.8.8.8"]["confidence"], 85)

    def test_threatfox_ip_port(self):
        source = Source("ThreatFox", "https://example.com", ("ips",), "threatfox", 94, "https://example.com")
        store = {"urls": {}, "ips": {}, "hashes": {}}
        row = '"2026-01-01","x","8.8.4.4:443","ip:port","botnet","x","x","family","x","90"'
        self.assertEqual(parse_threatfox(row, source, store), 1)
        self.assertIn("8.8.4.4", store["ips"])

    def test_rank_limit(self):
        source = Source("IPsum", "https://example.com", ("ips",), "ipsum", 72, "https://example.com")
        store = {"urls": {}, "ips": {}, "hashes": {}}
        parse_ipsum("8.8.8.8 5\n8.8.4.4 4\n", source, store)
        ranked = rank_store(store)
        self.assertEqual([item["rank"] for item in ranked["ips"]], [1, 2])


if __name__ == "__main__":
    unittest.main()
