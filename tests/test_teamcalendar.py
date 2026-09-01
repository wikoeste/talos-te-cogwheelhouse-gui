import os
import unittest
from datetime import date
from unittest.mock import Mock, patch

from liono.common import teamcalendar


SAMPLE_ICAL = b"""BEGIN:VCALENDAR\r
VERSION:2.0\r
BEGIN:VEVENT\r
UID:all-day@example\r
DTSTART;VALUE=DATE:20260810\r
DTEND;VALUE=DATE:20260811\r
SUMMARY:All-day review\r
END:VEVENT\r
BEGIN:VEVENT\r
UID:timed@example\r
DTSTART:20260811T140000Z\r
DTEND:20260811T150000Z\r
SUMMARY:Timed review\r
LOCATION:Webex\r
END:VEVENT\r
END:VCALENDAR\r
"""


class TeamCalendarTests(unittest.TestCase):
    def setUp(self):
        teamcalendar.clear_cache()

    def test_mixed_all_day_and_timed_events_are_sorted(self):
        events = teamcalendar._parse_events(
            SAMPLE_ICAL, date(2026, 8, 1), date(2026, 9, 1)
        )

        self.assertEqual([event.summary for event in events], [
            "All-day review",
            "Timed review",
        ])

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_credentials_returns_configuration_error(self):
        with self.assertRaisesRegex(
            teamcalendar.CalendarConfigurationError,
            "CONFLUENCE_CALENDAR_URL",
        ):
            teamcalendar.load_month("2026-08")

    @patch.dict(
        os.environ,
        {
            "CONFLUENCE_CALENDAR_URL": "https://evil.example/calendar",
            "CONFLUENCE_CALENDAR_USERNAME": "service-user",
            "CONFLUENCE_CALENDAR_API_TOKEN": "secret",
        },
        clear=True,
    )
    def test_credentials_cannot_be_sent_to_unapproved_host(self):
        with self.assertRaisesRegex(
            teamcalendar.CalendarConfigurationError,
            "confluence.vrt.sourcefire.com",
        ):
            teamcalendar.load_month("2026-08")

    @patch.dict(
        os.environ,
        {
            "CONFLUENCE_CALENDAR_URL": (
                "https://confluence.vrt.sourcefire.com/plugins/servlet/"
                "team-calendars/caldav/calendar-id"
            ),
            "CONFLUENCE_CALENDAR_API_TOKEN": "secret",
            "CONFLUENCE_CALENDAR_AUTH_MODE": "bearer",
        },
        clear=True,
    )
    def test_bearer_auth_does_not_require_username(self):
        _, username, secret, _, auth_mode = teamcalendar._configuration()
        auth, headers = teamcalendar._request_credentials(username, secret, auth_mode)

        self.assertIsNone(auth)
        self.assertEqual(headers, {"Authorization": "Bearer secret"})

    def test_unauthorized_response_has_actionable_bearer_message(self):
        response = Mock(status_code=401, headers={}, content=b"")

        with self.assertRaisesRegex(
            teamcalendar.CalendarFetchError,
            "rejected the configured Bearer token.*HTTP 401",
        ):
            teamcalendar._checked_content(response, "bearer")

    @patch.dict(
        os.environ,
        {
            "CONFLUENCE_CALENDAR_URL": (
                "https://confluence.vrt.sourcefire.com/plugins/servlet/"
                "team-calendars/caldav/calendar-id"
            ),
            "CONFLUENCE_CALENDAR_API_TOKEN": "secret",
            "CONFLUENCE_CALENDAR_AUTH_MODE": "basic",
        },
        clear=True,
    )
    def test_basic_auth_requires_username(self):
        with self.assertRaisesRegex(
            teamcalendar.CalendarConfigurationError,
            "USERNAME is required",
        ):
            teamcalendar._configuration()


if __name__ == "__main__":
    unittest.main()
