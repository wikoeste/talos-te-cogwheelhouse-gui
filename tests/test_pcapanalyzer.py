import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from liono.common import pcapanalyzer


RULE = (
    'alert tcp any any -> any 80 (msg:"Admin request"; '
    'content:"GET"; nocase; content:"/admin|3f|"; distance:1; within:32; '
    'sid:1000001; rev:1;)'
)


class FakeCapture(list):
    def close(self):
        return None


class PCAPAnalyzerTests(unittest.TestCase):
    def test_parses_text_hex_and_relative_content_options(self):
        parsed = pcapanalyzer.parse_rule(RULE)

        self.assertEqual(parsed["sid"], "1000001")
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["contents"][0]["value"], b"GET")
        self.assertTrue(parsed["contents"][0]["nocase"])
        self.assertEqual(parsed["contents"][1]["value"], b"/admin?")
        self.assertEqual(parsed["contents"][1]["distance"], 1)
        self.assertEqual(parsed["contents"][1]["within"], 32)

    def test_matches_content_and_reports_offsets(self):
        parsed = pcapanalyzer.parse_rule(RULE)

        matched, details = pcapanalyzer.match_contents(
            b"get /admin?user=1", parsed["contents"]
        )

        self.assertTrue(matched)
        self.assertEqual(details[0]["offset"], 0)
        self.assertEqual(details[1]["offset"], 4)

    def test_parses_snort3_inline_modifiers_and_line_continuations(self):
        rule = (
            "alert tcp any any -> any 80 ( \\\n"
            'content:"GET",nocase,fast_pattern; \\\n'
            'content:"/admin",distance 1,within:32; sid:7; ) \\'
        )

        parsed = pcapanalyzer.parse_rule(rule)

        self.assertTrue(parsed["contents"][0]["nocase"])
        self.assertEqual(parsed["contents"][1]["distance"], 1)
        self.assertEqual(parsed["contents"][1]["within"], 32)
        self.assertIn("fast_pattern", parsed["ignored_options"])

    def test_parses_snort3_service_header_rule(self):
        parsed = pcapanalyzer.parse_rule(
            'alert http (msg:"Request"; http_uri; content:"/admin",fast_pattern,nocase; '
            'pcre:"/one|two/im"; sid:41853;)'
        )

        self.assertEqual(parsed["protocol"], "http")
        self.assertTrue(parsed["service_header"])
        self.assertEqual(parsed["source_net"], "any")
        self.assertTrue(parsed["contents"][0]["nocase"])
        self.assertIn("service header: http", parsed["ignored_options"])
        self.assertEqual(parsed["pcres"][0]["source"], "one|two")
        self.assertTrue(parsed["pcres"][0]["supported"])

    def test_pcre_matches_in_rule_order_with_relative_cursor_and_flags(self):
        parsed = pcapanalyzer.parse_rule(
            'alert tcp any any -> any 80 (content:"GET"; '
            'pcre:"/\\s+\\/ADMIN\\?user=\\d+/Ri"; sid:9;)'
        )

        matched, contents, pcres = pcapanalyzer.match_payload_checks(
            b"GET /admin?user=42", parsed["payload_checks"]
        )

        self.assertTrue(matched)
        self.assertTrue(contents[0]["matched"])
        self.assertTrue(pcres[0]["matched"])
        self.assertTrue(pcres[0]["relative"])
        self.assertEqual(pcres[0]["offset"], 3)
        self.assertEqual(pcres[0]["match_end"], 18)

    def test_pcre_only_and_negated_rules_are_supported(self):
        parsed = pcapanalyzer.parse_rule(
            'alert tcp any any -> any any (pcre:!"/password=/i"; sid:10;)'
        )

        clean, _, clean_pcres = pcapanalyzer.match_payload_checks(
            b"username=guest", parsed["payload_checks"]
        )
        rejected, _, rejected_pcres = pcapanalyzer.match_payload_checks(
            b"PASSWORD=secret", parsed["payload_checks"]
        )

        self.assertTrue(clean)
        self.assertTrue(clean_pcres[0]["matched"])
        self.assertFalse(rejected)
        self.assertFalse(rejected_pcres[0]["matched"])

    def test_unsupported_pcre_flag_is_reported_as_non_match(self):
        parsed = pcapanalyzer.parse_rule(
            'alert tcp any any -> any any (pcre:"/abc/G"; sid:11;)'
        )

        matched, _, pcres = pcapanalyzer.match_payload_checks(
            b"abc", parsed["payload_checks"]
        )

        self.assertFalse(matched)
        self.assertFalse(parsed["pcres"][0]["supported"])
        self.assertIn("Unsupported Snort PCRE flag", pcres[0]["unsupported_reason"])

    def test_analyze_summarizes_packet_and_full_rule_match(self):
        packet = SimpleNamespace(
            transport_layer="TCP",
            highest_layer="HTTP",
            ip=SimpleNamespace(src="192.0.2.10", dst="198.51.100.20"),
            tcp=SimpleNamespace(
                srcport="49152",
                dstport="80",
                payload="47:45:54:20:2f:61:64:6d:69:6e:3f:75:73:65:72:3d:31",
            ),
            sniff_timestamp="1788278400.0",
            length="71",
        )
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "sample.pcap"
            pcap.write_bytes(b"pcap-data")
            with patch.object(
                pcapanalyzer.pyshark,
                "FileCapture",
                return_value=FakeCapture([packet]),
            ):
                result = pcapanalyzer.analyze(pcap, RULE)

        self.assertEqual(result["capture"]["packets_analyzed"], 1)
        self.assertEqual(result["capture"]["protocols"], [("TCP", 1)])
        self.assertEqual(result["matched_packet_count"], 1)
        self.assertTrue(result["matches"][0]["full_match"])
        self.assertEqual(result["matches"][0]["payload_length"], 17)

        sections = pcapanalyzer.summary_sections(result)
        self.assertEqual(
            [section["label"] for section in sections],
            ["CONTENT OPTIONS", "MATCHED PACKETS", "PACKET SAMPLE"],
        )
        self.assertEqual(sections[0]["title"], "Values evaluated")
        self.assertIn('Content #1: "GET"', sections[0]["items"][0])
        self.assertEqual(sections[1]["title"], "Header, content, and PCRE matches")
        self.assertIn("Packet 1: TCP", sections[1]["items"][0])
        self.assertEqual(sections[2]["title"], "Decoded capture inventory")
        self.assertIn("Payload: 17 B", sections[2]["items"][0])

        replay_sections = pcapanalyzer.summary_sections(
            result, include_packet_sample=False
        )
        self.assertEqual(
            [section["label"] for section in replay_sections],
            ["CONTENT OPTIONS", "MATCHED PACKETS"],
        )

    def test_rejects_rule_without_content(self):
        with self.assertRaisesRegex(pcapanalyzer.AnalysisError, "content or pcre option"):
            pcapanalyzer.parse_rule(
                'alert tcp any any -> any any (msg:"No content"; sid:1; rev:1;)'
            )

    def test_summary_lines_reports_verdict_and_packet_counts(self):
        summary = pcapanalyzer.summary_lines(
            {
                "capture": {
                    "filename": "sample.pcap",
                    "packets_analyzed": 12,
                    "protocols": [("TCP", 10), ("UDP", 2)],
                    "limit_reached": False,
                },
                "rule": {"contents": [{}, {}], "pcres": [{}], "ignored_options": []},
                "matched_packet_count": 1,
                "matches": [{"number": 7}],
            }
        )

        self.assertIn("Analyzer verdict: MATCH", summary)
        self.assertIn("Packets analyzed: 12", summary)
        self.assertIn("Packets matching all supported rule conditions: 1", summary)
        self.assertIn("PCRE options evaluated: 1", summary)
        self.assertIn("Matching packet numbers: 7", summary)


if __name__ == "__main__":
    unittest.main()
