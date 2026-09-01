import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from liono.common import replaypost


class ReplayPostStoreTests(unittest.TestCase):
    def test_result_is_private_and_loadable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            replaypost, "STORE_DIR", Path(directory) / "replay-posts"
        ):
            token = replaypost.store_result(
                sid="66965",
                snort_version="Version 3.12.2",
                policy="Local Rules Only",
                capture_summary=["Protocol: TCP"],
                content_analysis=["Analyzer verdict: MATCH"],
                runtime_alerts=["######", "alert output", "######"],
            )
            stored_file = replaypost.STORE_DIR / f"{token}.json"
            result = replaypost.load_result(token)

            self.assertEqual(result["sid"], "66965")
            self.assertEqual(result["runtime_alerts"][1], "alert output")
            self.assertEqual(result["content_analysis"], ["Analyzer verdict: MATCH"])
            self.assertEqual(stat.S_IMODE(stored_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(replaypost.STORE_DIR.stat().st_mode), 0o700)

            replaypost.discard_result(token)
            self.assertFalse(stored_file.exists())

    def test_invalid_token_is_rejected(self):
        with self.assertRaises(replaypost.ReplayPostError):
            replaypost.load_result("../../not-safe")


if __name__ == "__main__":
    unittest.main()
