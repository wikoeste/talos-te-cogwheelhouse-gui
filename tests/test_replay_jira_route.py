import unittest
from unittest.mock import patch

import server


class ReplayJiraRouteTests(unittest.TestCase):
    def setUp(self):
        server.app.config.update(TESTING=True)
        self.client = server.app.test_client()
        with self.client.session_transaction() as session:
            session["username"] = "analyst"
            session["pw"] = "session-password"
            session["replay_csrf"] = "csrf-token"

    def test_server_stored_results_are_posted_to_private_cog_comment(self):
        replay = {
            "sid": "66965",
            "snort_version": "Version 3.12.2",
            "policy": "Local Rules Only",
            "capture_summary": ["Protocol: TCP"],
            "runtime_alerts": ["######", "alert", "######"],
        }
        with patch.object(server.settings, "uname", "analyst"), patch.object(
            server.settings, "jkey", "profile-api-token"
        ), patch.object(server.replaypost, "load_result", return_value=replay), patch.object(
            server.replaypost, "discard_result"
        ) as discard, patch.object(
            server.jirapost, "post_replay_results", return_value="COG-24680"
        ) as post:
            response = self.client.post(
                "/testpcap/results/jira",
                data={
                    "csrf_token": "csrf-token",
                    "replay_post_token": "opaque-token",
                    "post_to_jira": "yes",
                    "jira_ticket": "cog-24680",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Replay results posted successfully", response.data)
        post.assert_called_once_with(
            "COG-24680",
            replay,
            username="analyst",
            password="profile-api-token",
        )
        discard.assert_called_once_with("opaque-token")

    def test_jira_post_rejects_invalid_csrf(self):
        with patch.object(server.replaypost, "load_result") as load:
            response = self.client.post(
                "/testpcap/results/jira",
                data={"csrf_token": "wrong", "post_to_jira": "yes"},
            )

        self.assertEqual(response.status_code, 400)
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
