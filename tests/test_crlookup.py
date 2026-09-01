import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from liono.common import crlookup, rulesearch


class FakeResponse:
    status_code = 200
    content = b'{"data":{"cve":"CVE-2026-63030"}}'

    def raise_for_status(self):
        return None

    def json(self):
        return {"data": {"cve": "CVE-2026-63030"}}


class FakeHTTP:
    def get(self, *args, **kwargs):
        self.arguments = (args, kwargs)
        return FakeResponse()


class CRLookupTests(unittest.TestCase):
    def test_lookup_canonicalizes_and_uses_tls(self):
        http = FakeHTTP()
        with patch.dict(os.environ, {"ANALYSIS_API_KEY": "private-key"}):
            cve, payload = crlookup.lookup(" cve-2026-63030 ", http=http)
        self.assertEqual(cve, "CVE-2026-63030")
        self.assertEqual(payload["data"]["cve"], cve)
        self.assertEqual(http.arguments[1]["params"], {"cve": cve, "tickets": "true"})
        self.assertIs(http.arguments[1]["verify"], True)

    def test_normalize_cves_deduplicates_and_rejects_invalid_values(self):
        self.assertEqual(
            crlookup.normalize_cves("cve-2026-63030, CVE-2026-63030 CVE-2025-12345"),
            ["CVE-2026-63030", "CVE-2025-12345"],
        )
        with self.assertRaises(crlookup.CRValidationError):
            crlookup.normalize_cves("not-a-cve")

    def test_research_and_sid_extraction_use_explicit_snort_fields(self):
        payload = {
            "proof_of_concept": "https://example.test/poc",
            "snort": {"sids": "66965, 66966"},
            "metadata": {"sid": "99999"},
            "snort_signature_feasible": True,
        }
        self.assertEqual(crlookup.extract_snort_sids(payload), ["66965", "66966"])
        research = crlookup.extract_research(payload)
        self.assertEqual(research["exploit_status"], "Reported")
        self.assertEqual(research["signature_feasibility"], "Yes")

    def test_downloaded_rules_match_cve_and_sid(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "protocol.rules").write_text(
                'alert tcp any any -> any any (reference:cve,2026-63030; sid:66965;)\n',
                encoding="utf-8",
            )
            cve_matches = rulesearch.find_cve_signatures(["CVE-2026-63030"], [directory])
            sid_matches = rulesearch.find_signatures(["66965"], [directory])
        self.assertEqual(cve_matches[0]["sid"], "66965")
        self.assertEqual(sid_matches[0]["source_name"], "protocol.rules")


if __name__ == "__main__":
    unittest.main()
