import unittest
from unittest.mock import Mock, patch

from liono.common import bpsearch_queries


class BPSearchQueryTests(unittest.TestCase):
    def test_menu_matches_standalone_bpsearch_options(self):
        self.assertEqual(
            list(bpsearch_queries.menu_options()),
            [
                "signature", "cloud_ioc", "bpfps", "cloud_ioc_events",
                "connector_errors", "sha_or_sig", "sha256",
                "connector_events", "company_guid",
            ],
        )

    def test_moaec_query_uses_structured_json_and_tls(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "hits": {
                "total": {"value": 1},
                "hits": [{"fields": {"event_type": ["BP_EVENT"], "data.details.sig_id": ["12345678901234"]}}],
            }
        }
        values = {
            "business_guid": "12345678-1234-1234-1234-123456789abc",
            "bp_sig_id": "12345678901234",
            "days": "7",
        }
        environment = {
            "BPSEARCH_MOAEC_URL": "https://moaec.example.test/",
            "BPSEARCH_MOAEC_USERNAME": "analyst",
            "BPSEARCH_MOAEC_PASSWORD": "secret-from-environment",
        }
        with patch.dict("os.environ", environment, clear=False), patch.object(
            bpsearch_queries.requests, "post", return_value=response
        ) as post:
            result = bpsearch_queries.search("bpfps", values)

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["rows"][0]["signature_id"], "12345678901234")
        payload = post.call_args.kwargs["json"]
        self.assertIsInstance(payload, dict)
        self.assertNotIn("12345678901234", str(post.call_args.args[0]))
        self.assertNotIn("verify", post.call_args.kwargs)

    def test_invalid_guid_and_period_are_rejected_before_network(self):
        with patch.object(bpsearch_queries.requests, "post") as post:
            with self.assertRaises(bpsearch_queries.BPSearchError):
                bpsearch_queries.search(
                    "connector_events",
                    {"agent_guid": "not-a-guid", "days": "365"},
                )
        post.assert_not_called()

    def test_company_lookup_uses_params_not_url_concatenation(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"businesses": [{"guid": "guid-1", "business": "Example Corp"}]}
        environment = {
            "BPSEARCH_INTEL_API_URL": "https://intel.example.test/",
            "BPSEARCH_INTEL_API_KEY": "environment-key",
        }
        with patch.dict("os.environ", environment, clear=False), patch.object(
            bpsearch_queries.requests, "get", return_value=response
        ) as get:
            result = bpsearch_queries.search("company_guid", {"company_name": "Example Corp"})

        self.assertEqual(result["rows"][0]["company"], "Example Corp")
        self.assertNotIn("Example", get.call_args.args[0])
        self.assertEqual(get.call_args.kwargs["params"]["name"], "Example Corp")


if __name__ == "__main__":
    unittest.main()
