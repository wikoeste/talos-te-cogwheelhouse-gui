import unittest
from unittest.mock import patch

import server


class PCAPAnalyzerRouteTests(unittest.TestCase):
    def setUp(self):
        server.app.config.update(TESTING=True)
        self.client = server.app.test_client()
        with self.client.session_transaction() as session:
            session["username"] = "analyst"
            session["replay_csrf"] = "csrf-token"

    def test_pigreplay_tile_and_menu_link_to_analyzer(self):
        menu = self.client.get("/pigreplay").get_data(as_text=True)
        self.assertIn('href="/analyzepcap"', menu)
        self.assertIn("Analyze PCAP", menu)

    def test_analyzer_results_render_structured_output(self):
        analysis = {
            "capture": {
                "filename": "capture.pcap", "file_size": 36,
                "packets_analyzed": 1, "wire_bytes": 60,
                "first_timestamp": "2026-09-01T12:00:00Z",
                "last_timestamp": "2026-09-01T12:00:00Z",
                "protocols": [("TCP", 1)], "top_conversations": [],
                "limit_reached": False,
            },
            "rule": {
                "sid": "66965", "text": "alert tcp any any -> any any",
                "message": "Test", "protocol": "tcp", "source_net": "any",
                "source_port": "any", "direction": "->",
                "destination_net": "any", "destination_port": "any",
                "ignored_options": [], "contents": [], "pcres": [],
            },
            "matched_packet_count": 0, "matches": [], "packets": [],
            "packet_rows_truncated": False,
        }
        with patch.object(server, "analyzer_pcap", return_value="/tmp/capture.pcap"), patch.object(
            server.pcapanalyzer, "analyze", return_value=analysis
        ):
            response = self.client.post(
                "/analyzepcap/results",
                data={
                    "csrf_token": "csrf-token", "pcap": "capture.pcap",
                    "rule": "alert tcp any any -> any any (content:\"GET\"; sid:66965;)",
                },
            )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("PACKETS ANALYZED", body)
        self.assertIn("CAPTURE DATA", body)
        self.assertIn("PACKET SAMPLE", body)


if __name__ == "__main__":
    unittest.main()
