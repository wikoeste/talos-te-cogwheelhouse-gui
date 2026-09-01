import unittest
from datetime import date
from types import SimpleNamespace
from unittest.mock import Mock

from liono.common import jsearch


def issue(key, *, priority="P1", resolution=None, issue_type="Email", customer="Example Corp"):
    return SimpleNamespace(
        key=key,
        fields=SimpleNamespace(
            summary=f"Summary for {key}",
            priority=SimpleNamespace(name=priority),
            created="2026-08-17T10:30:00.000-0400",
            resolutiondate="2026-08-18T11:45:00.000-0400" if resolution else None,
            status=SimpleNamespace(name="Resolved" if resolution else "Open"),
            resolution=SimpleNamespace(name=resolution) if resolution else None,
            issuetype=SimpleNamespace(name=issue_type),
            customfield_13528=customer,
        ),
    )


class JiraMetricsTests(unittest.TestCase):
    def test_queries_cover_priority_created_and_invalid_resolved_windows(self):
        jira = Mock()
        jira.search_issues.side_effect = [
            [issue("COG-100", priority="P1"), issue("COG-101", priority="P2")],
            [issue("COG-102", resolution="Invalid")],
            [issue("COG-103", issue_type="Mailer", customer="Mailer Customer")],
            [
                *[issue(f"COG-{200 + number}", customer="High Volume Corp") for number in range(6)],
                issue("COG-206", issue_type="Endpoint", customer="Small Corp"),
                issue("COG-207", issue_type="New Type", customer=None),
            ],
        ]

        date_range = jsearch.resolve_metric_date_range("30", today=date(2026, 8, 19))
        metrics = jsearch.jira_metrics(date_range=date_range, jira=jira)

        self.assertEqual([row["key"] for row in metrics["priority"]], ["COG-100", "COG-101"])
        self.assertEqual(metrics["invalid"][0]["resolution"], "Invalid")
        self.assertEqual(metrics["invalid"][0]["resolved"], "2026-08-18")
        self.assertEqual(metrics["mailer"][0]["key"], "COG-103")
        self.assertEqual(metrics["customers"], [{"customer": "High Volume Corp", "count": 6}])
        self.assertEqual(
            metrics["products"],
            [
                {"product": "IPAS", "count": 6},
                {"product": "FILE", "count": 1},
                {"product": "SNORT", "count": 0},
                {"product": "SBRS", "count": 0},
                {"product": "WEB", "count": 0},
                {"product": "OTHER", "count": 0},
                {"product": "UNMAPPED", "count": 1},
                {"product": "TOTAL COG REQUESTS", "count": 8},
            ],
        )
        priority_call, invalid_call, mailer_call, all_call = jira.search_issues.call_args_list
        self.assertIn("priority in (P1, P2)", priority_call.args[0])
        self.assertIn('created >= "2026-07-21"', priority_call.args[0])
        self.assertIn('created < "2026-08-20"', priority_call.args[0])
        self.assertIn("resolution = Invalid", invalid_call.args[0])
        self.assertIn('resolved >= "2026-07-21"', invalid_call.args[0])
        self.assertIn("issuetype = Mailer", mailer_call.args[0])
        self.assertIn('created >= "2026-07-21"', mailer_call.args[0])
        self.assertEqual(
            all_call.args[0],
            'project = COG AND created >= "2026-07-21" '
            'AND created < "2026-08-20" ORDER BY created DESC',
        )
        self.assertEqual(metrics["date_range"], date_range)
        for call in jira.search_issues.call_args_list:
            self.assertIs(call.kwargs["maxResults"], False)
            self.assertEqual(call.kwargs["fields"], jsearch.JIRA_METRIC_FIELDS)

    def test_customer_threshold_is_strictly_more_than_five(self):
        issues = [issue(f"COG-{number}", customer="Exactly Five") for number in range(5)]

        self.assertEqual(jsearch._high_volume_customers(issues), [])

    def test_jira_errors_are_user_safe(self):
        jira = Mock()
        jira.search_issues.side_effect = ValueError("sensitive backend response")

        with self.assertRaisesRegex(jsearch.JiraMetricsError, "Unable to retrieve Jira Metrics"):
            jsearch.jira_metrics(jira=jira)

    def test_cisco_fiscal_quarter_uses_published_fy26_boundaries(self):
        quarters = {
            option.key: option
            for option in jsearch.fiscal_quarter_options(
                today=date(2026, 4, 1), count=4
            )
        }

        self.assertEqual(quarters["FY2026-Q3"].start, date(2026, 1, 25))
        self.assertEqual(quarters["FY2026-Q3"].end, date(2026, 4, 25))
        self.assertEqual(quarters["FY2026-Q2"].start, date(2025, 10, 26))
        self.assertEqual(quarters["FY2026-Q2"].end, date(2026, 1, 24))

    def test_date_range_inputs_are_allowlisted(self):
        with self.assertRaises(jsearch.JiraMetricsPeriodError):
            jsearch.resolve_metric_date_range(
                '7 OR project = RESBZ', today=date(2026, 8, 19)
            )
        with self.assertRaises(jsearch.JiraMetricsPeriodError):
            jsearch.resolve_metric_date_range(
                'fiscal', quarter='FY2026-Q4" OR project = RESBZ',
                today=date(2026, 8, 19),
            )

    def test_current_cisco_fiscal_quarter_defaults_when_not_selected(self):
        date_range = jsearch.resolve_metric_date_range(
            "fiscal", today=date(2026, 8, 19)
        )

        self.assertEqual(date_range.key, "FY2027-Q1")
        self.assertEqual(date_range.start, date(2026, 7, 26))
        self.assertEqual(date_range.end, date(2026, 10, 24))


if __name__ == "__main__":
    unittest.main()
