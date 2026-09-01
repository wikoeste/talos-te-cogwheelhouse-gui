import unittest
from unittest.mock import Mock

from liono.common import jirapost


class JiraPostTests(unittest.TestCase):
    def setUp(self):
        self.replay = {
            "sid": "66965",
            "snort_version": "Version 3.12.2",
            "policy": "Local Rules Only",
            "capture_summary": ["Protocol: TCP", "Source IP: 192.0.2.10"],
            "content_analysis": [
                "Analyzer verdict: MATCH",
                "[[PIGREPLAY_SECTION]] MATCHED PACKETS",
                "[[PIGREPLAY_TITLE]] Header, content, and PCRE matches",
                "Packet 1: Match",
            ],
            "runtime_alerts": ["######", "[1:66965:1] test alert", "######"],
        }

    def test_validate_cog_ticket_canonicalizes_and_restricts_project(self):
        self.assertEqual(jirapost.validate_cog_ticket(" cog-24680 "), "COG-24680")
        with self.assertRaises(jirapost.JiraPostError):
            jirapost.validate_cog_ticket("RESBZ-24680")

    def test_post_replay_results_adds_private_comment(self):
        issue = Mock(key="COG-24680")
        jira = Mock()
        jira.issue.return_value = issue

        ticket = jirapost.post_replay_results("cog-24680", self.replay, jira=jira)

        self.assertEqual(ticket, "COG-24680")
        jira.issue.assert_called_once_with("COG-24680")
        _, comment = jira.add_comment.call_args.args
        self.assertIn("Snort PCAP Replay Results", comment)
        self.assertIn("[1:66965:1] test alert", comment)
        self.assertIn("PCAP analyzer summary", comment)
        self.assertIn("h4. MATCHED PACKETS", comment)
        self.assertNotIn("PACKET SAMPLE", comment)
        self.assertEqual(jira.add_comment.call_args.kwargs["visibility"], jirapost.PRIVATE)

    def test_post_cr_results_adds_private_comment(self):
        issue = Mock(key="RESBZ-24680")
        jira = Mock()
        jira.issue.return_value = issue
        batch = [{
            "cve": "CVE-2026-63030", "error": None,
            "research": {"exploit_status": "Reported", "signature_feasibility": "Yes"},
            "snort_signatures": [{"sid": "66965", "source_name": "test.rules", "rule": "alert tcp any any -> any any (sid:66965;)"}],
        }]

        ticket = jirapost.post_cr_results("resbz-24680", batch, jira=jira)

        self.assertEqual(ticket, "RESBZ-24680")
        self.assertIn("CVE CR Analysis Results", jira.add_comment.call_args.args[1])
        self.assertEqual(jira.add_comment.call_args.kwargs["visibility"], jirapost.PRIVATE)


if __name__ == "__main__":
    unittest.main()
