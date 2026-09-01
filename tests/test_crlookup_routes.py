import unittest
from unittest.mock import patch

import server


class CRLookupRouteTests(unittest.TestCase):
    def setUp(self):
        server.app.config.update(TESTING=True)
        self.client = server.app.test_client()
        with self.client.session_transaction() as flask_session:
            flask_session["username"] = "tester"
            flask_session["cr_csrf"] = "valid-token"

    def test_page_menu_and_pigreplay_tile_link_to_analysis(self):
        page = self.client.get("/crlookup")
        dashboard = self.client.get("/pigreplay")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"CVE CR Analysis", page.data)
        self.assertIn(b'href="/crlookup"', dashboard.data)

    def test_results_render_research_and_rule_match(self):
        api_result = [{
            "cve": "CVE-2026-63030", "error": None,
            "payload": {"proof_of_concept": "https://example.test/poc", "snort": {"sid": "66965"}},
        }]
        rule = {"cve": "CVE-2026-63030", "sid": "66965", "rule": "alert tcp any any -> any any (sid:66965;)", "source_name": "test.rules", "source_path": "/rules/test.rules", "line_number": 1, "match_source": "CVE reference"}
        with patch.object(server.crlookup_api, "lookup_many", return_value=api_result), \
             patch.object(server.rs, "find_cve_signatures", return_value=[rule]), \
             patch.object(server.rs, "find_signatures", return_value=[]):
            response = self.client.post("/crlookup/results", data={"csrf_token": "valid-token", "cves": "CVE-2026-63030"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Exploit evidence", response.data)
        self.assertIn(b"SID 66965", response.data)

    def test_results_reject_invalid_csrf(self):
        response = self.client.post("/crlookup/results", data={"csrf_token": "wrong", "cves": "CVE-2026-63030"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
