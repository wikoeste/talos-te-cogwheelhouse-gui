import unittest

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReplayResultsTemplateTests(unittest.TestCase):
    def test_alert_block_is_red_and_output_is_escaped(self):
        environment = Environment(
            loader=FileSystemLoader("templates"),
            autoescape=select_autoescape(),
        )
        url_for = lambda endpoint, **values: "/" + values.get("filename", endpoint)
        html = environment.get_template("replay/replayResults.html").render(
            url_for=url_for,
            snortversion="Version 3.12.2",
            pol="Local Rules Only",
            rule="alert tcp any any -> any any (sid:1;)",
            pcapdata=["Protocol: TCP"],
            results=["runtime", "######", "<alert>", "######", "summary"],
            replay_jira_copy="Jira copy",
            replay_post_token="token",
            replay_post_error=None,
            csrf_token="csrf",
            analyzer_results=[{
                "filename": "capture.pcap",
                "error": None,
                "analysis": {
                    "capture": {
                        "packets_analyzed": 1, "file_size": 36, "wire_bytes": 60,
                        "first_timestamp": "2026-09-01T12:00:00Z",
                        "last_timestamp": "2026-09-01T12:00:00Z",
                        "protocols": [("TCP", 1)], "top_conversations": [],
                        "limit_reached": False,
                    },
                    "rule": {"contents": [], "pcres": []},
                    "matched_packet_count": 0, "matches": [],
                },
            }],
        )

        self.assertEqual(html.count('class="replay-alert-row"'), 3)
        self.assertIn("&lt;alert&gt;", html)
        self.assertIn("Post these replay results to a COG ticket?", html)
        self.assertIn("PACKETS ANALYZED", html)
        self.assertIn("CAPTURE DATA", html)
        self.assertNotIn("PACKET SAMPLE", html)

    def test_runtime_preamble_is_orange_and_five_hash_alert_block_is_red(self):
        environment = Environment(
            loader=FileSystemLoader("templates"),
            autoescape=select_autoescape(),
        )
        url_for = lambda endpoint, **values: "/" + values.get("filename", endpoint)
        html = environment.get_template("replay/replayResults.html").render(
            url_for=url_for,
            snortversion="Version 3.12.2",
            pol="Security",
            rule="alert tcp any any -> any any (sid:1;)",
            pcapdata=["Protocol: TCP"],
            results=[
                "====SNORT3 RUNTIME LOG DATA====",
                "CompletedProcess(args=['snort'], returncode=0, stdout=b'",
                "##### pcap.pcap #####",
                "No alerts",
                "#####",
            ],
            replay_jira_copy="Jira copy",
            replay_post_token=None,
            replay_post_error=None,
            csrf_token="csrf",
        )

        self.assertEqual(html.count('class="replay-runtime-log-row"'), 2)
        self.assertEqual(html.count('class="replay-alert-row"'), 3)


if __name__ == "__main__":
    unittest.main()
