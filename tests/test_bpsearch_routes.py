import unittest
from unittest.mock import patch

import server


class BPSearchRouteTests(unittest.TestCase):
    def setUp(self):
        server.app.config.update(TESTING=True)
        self.client = server.app.test_client()
        with self.client.session_transaction() as session:
            session["username"] = "analyst"
            session["bpsearch_csrf"] = "bp-csrf"

    def test_bpsearch_page_lists_all_menu_options(self):
        response = self.client.get("/bpSearch?tool=connector_errors")

        self.assertEqual(response.status_code, 200)
        for label in (
            b"BP Sig Search", b"Cloud IOC Sig Search",
            b"BP False Positives", b"Cloud IOC Events", b"SE Connector Errors",
            b"SHA256 or BP SigID", b"SHA256 Only", b"SE Connector Events",
            b"Company Name to GUID",
        ):
            self.assertIn(label, response.data)
        self.assertIn(b'name="csrf_token" value="bp-csrf"', response.data)

    def test_query_route_renders_structured_results(self):
        result = {
            "option": "connector_events",
            "label": "SE Connector Events",
            "summary": "Agent test",
            "columns": (("event_type", "Event"),),
            "rows": [{"event_type": "POLICY_FETCH_FAILED"}],
            "total": 1,
        }
        with patch.object(server.bpsearch_queries, "search", return_value=result) as search:
            response = self.client.post(
                "/bpsearch/query",
                data={
                    "csrf_token": "bp-csrf",
                    "option": "connector_events",
                    "agent_guid": "12345678-1234-1234-1234-123456789abc",
                    "days": "7",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"POLICY_FETCH_FAILED", response.data)
        search.assert_called_once()

    def test_query_route_rejects_invalid_csrf(self):
        with patch.object(server.bpsearch_queries, "search") as search:
            response = self.client.post(
                "/bpsearch/query",
                data={"csrf_token": "wrong", "option": "connector_events"},
            )

        self.assertEqual(response.status_code, 400)
        search.assert_not_called()


if __name__ == "__main__":
    unittest.main()
