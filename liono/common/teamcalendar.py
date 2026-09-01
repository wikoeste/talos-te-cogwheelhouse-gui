from __future__ import annotations

"""Read-only Confluence Team Calendar integration."""

import calendar
import hashlib
import os
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from xml.etree import ElementTree

import recurring_ical_events
import requests
from dotenv import load_dotenv
from icalendar import Calendar
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)

DEFAULT_CONFLUENCE_HOST = "confluence.vrt.sourcefire.com"
DEFAULT_WEB_URL = "https://confluence.vrt.sourcefire.com/calendar/mycalendar.action"
HTTP_TIMEOUT = (5, 30)
MAX_CALENDAR_BYTES = 5_000_000
CACHE_SECONDS = 300


class CalendarConfigurationError(RuntimeError):
    """Raised when required calendar configuration is missing or unsafe."""


class CalendarFetchError(RuntimeError):
    """Raised when Confluence calendar data cannot be retrieved or parsed."""


@dataclass(frozen=True)
class TeamCalendarEvent:
    summary: str
    start: date | datetime
    end: date | datetime
    all_day: bool
    location: str


@dataclass(frozen=True)
class CalendarDay:
    value: date
    in_month: bool
    is_today: bool
    events: tuple[TeamCalendarEvent, ...]


@dataclass(frozen=True)
class CalendarMonth:
    title: str
    month_key: str
    previous_month: str
    next_month: str
    weeks: tuple[tuple[CalendarDay, ...], ...]
    event_count: int
    source_url: str


_http = requests.Session()
_http.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "REPORT"}),
        )
    ),
)
_cache = {}
_cache_lock = threading.Lock()


def _boolean_setting(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _timezone():
    name = os.getenv("TEAM_CALENDAR_TIMEZONE", "America/New_York")
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise CalendarConfigurationError(f"Unknown TEAM_CALENDAR_TIMEZONE: {name}") from exc


def _month_start(month_value=None):
    if not month_value:
        today = datetime.now(_timezone()).date()
        return today.replace(day=1)
    try:
        return datetime.strptime(month_value, "%Y-%m").date().replace(day=1)
    except ValueError as exc:
        raise CalendarConfigurationError("Calendar month must use YYYY-MM format.") from exc


def _shift_month(value, offset):
    month_index = value.year * 12 + value.month - 1 + offset
    return date(month_index // 12, month_index % 12 + 1, 1)


def _configuration():
    source_url = os.getenv("CONFLUENCE_CALENDAR_URL", "").strip()
    username = os.getenv("CONFLUENCE_CALENDAR_USERNAME", "").strip()
    secret = os.getenv("CONFLUENCE_CALENDAR_API_TOKEN", "").strip()
    mode = os.getenv("CONFLUENCE_CALENDAR_MODE", "caldav").strip().lower()
    auth_mode = os.getenv("CONFLUENCE_CALENDAR_AUTH_MODE", "bearer").strip().lower()
    allowed_host = os.getenv("CONFLUENCE_CALENDAR_ALLOWED_HOST", DEFAULT_CONFLUENCE_HOST).strip().lower()

    if not source_url or not secret:
        raise CalendarConfigurationError(
            "Team Calendar needs CONFLUENCE_CALENDAR_URL and "
            "CONFLUENCE_CALENDAR_API_TOKEN."
        )
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or parsed.hostname != allowed_host:
        raise CalendarConfigurationError(
            f"CONFLUENCE_CALENDAR_URL must use HTTPS on {allowed_host}."
        )
    if parsed.username or parsed.password:
        raise CalendarConfigurationError("Do not place calendar credentials inside the URL.")
    if mode not in {"caldav", "ical"}:
        raise CalendarConfigurationError("CONFLUENCE_CALENDAR_MODE must be caldav or ical.")
    if auth_mode not in {"basic", "bearer"}:
        raise CalendarConfigurationError(
            "CONFLUENCE_CALENDAR_AUTH_MODE must be basic or bearer."
        )
    if auth_mode == "basic" and not username:
        raise CalendarConfigurationError(
            "CONFLUENCE_CALENDAR_USERNAME is required when using Basic authentication."
        )
    return source_url, username, secret, mode, auth_mode


def _request_credentials(username, secret, auth_mode):
    if auth_mode == "bearer":
        return None, {"Authorization": f"Bearer {secret}"}
    return (username, secret), {}


def _calendar_query(start, end):
    start_utc = datetime.combine(start, datetime_time.min, tzinfo=timezone.utc)
    end_utc = datetime.combine(end, datetime_time.min, tzinfo=timezone.utc)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VEVENT">
        <c:time-range start="{start_utc:%Y%m%dT%H%M%SZ}" end="{end_utc:%Y%m%dT%H%M%SZ}"/>
      </c:comp-filter>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>"""


def _checked_content(response, auth_mode):
    if response.status_code == 401:
        credential_type = "Bearer token" if auth_mode == "bearer" else "Basic credentials"
        raise CalendarFetchError(
            f"Confluence rejected the configured {credential_type} (HTTP 401). "
            "Verify that the token is valid, then restart the application."
        )
    if response.status_code == 403:
        raise CalendarFetchError(
            "Confluence authenticated the calendar request but denied access (HTTP 403). "
            "Grant the account permission to view this Team Calendar."
        )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise CalendarFetchError(
            f"Confluence calendar request failed (HTTP {response.status_code})."
        ) from exc
    length = int(response.headers.get("Content-Length", "0") or 0)
    if length > MAX_CALENDAR_BYTES or len(response.content) > MAX_CALENDAR_BYTES:
        raise CalendarFetchError("The calendar response exceeded the 5 MB safety limit.")
    return response.content


def _fetch_calendar_bytes(source_url, username, secret, mode, auth_mode, start, end):
    auth, auth_headers = _request_credentials(username, secret, auth_mode)
    verify_tls = _boolean_setting("CONFLUENCE_CALENDAR_VERIFY_TLS", True)
    try:
        if mode == "ical":
            response = _http.get(
                source_url,
                auth=auth,
                headers={"Accept": "text/calendar", **auth_headers},
                timeout=HTTP_TIMEOUT,
                verify=verify_tls,
            )
            return _checked_content(response, auth_mode)

        response = _http.request(
            "REPORT",
            source_url,
            auth=auth,
            headers={
                "Content-Type": "application/xml; charset=utf-8",
                "Depth": "1",
                **auth_headers,
            },
            data=_calendar_query(start, end),
            timeout=HTTP_TIMEOUT,
            verify=verify_tls,
        )
        xml_data = _checked_content(response, auth_mode)
        root = ElementTree.fromstring(xml_data)
        calendar_nodes = root.findall(".//{urn:ietf:params:xml:ns:caldav}calendar-data")
        if not calendar_nodes:
            raise CalendarFetchError("Confluence returned no calendar event data.")
        merged = Calendar()
        merged.add("prodid", "-//Talos TE COG Wheelhouse//Team Calendar//EN")
        merged.add("version", "2.0")
        for node in calendar_nodes:
            if not node.text:
                continue
            source_calendar = Calendar.from_ical(node.text)
            for component in source_calendar.walk("VEVENT"):
                merged.add_component(component)
        return merged.to_ical()
    except CalendarFetchError:
        raise
    except requests.RequestException as exc:
        raise CalendarFetchError("Unable to retrieve Team Calendar data from Confluence.") from exc
    except ElementTree.ParseError as exc:
        raise CalendarFetchError("Confluence returned invalid CalDAV data.") from exc


def _as_local(value, local_timezone):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=local_timezone)
        return value.astimezone(local_timezone)
    return value


def _parse_events(calendar_bytes, start, end):
    try:
        parsed = Calendar.from_ical(calendar_bytes)
        components = recurring_ical_events.of(parsed).between(start, end)
    except Exception as exc:
        raise CalendarFetchError("Unable to parse Confluence calendar events.") from exc

    local_timezone = _timezone()
    events = []
    for component in components:
        raw_start = component.decoded("DTSTART")
        raw_end = component.decoded("DTEND", raw_start)
        event_start = _as_local(raw_start, local_timezone)
        event_end = _as_local(raw_end, local_timezone)
        events.append(
            TeamCalendarEvent(
                summary=str(component.get("SUMMARY", "Untitled event")),
                start=event_start,
                end=event_end,
                all_day=not isinstance(event_start, datetime),
                location=str(component.get("LOCATION", "")),
            )
        )
    def sort_key(event):
        if isinstance(event.start, datetime):
            sortable_start = event.start
        else:
            sortable_start = datetime.combine(
                event.start, datetime_time.min, tzinfo=local_timezone
            )
        return sortable_start, event.summary.casefold()

    return tuple(sorted(events, key=sort_key))


def _cached_events(start, end):
    source_url, username, secret, mode, auth_mode = _configuration()
    source_hash = hashlib.sha256(
        f"{source_url}|{username}|{mode}|{auth_mode}".encode("utf-8")
    ).hexdigest()
    key = (source_hash, start, end)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and now - cached[0] < CACHE_SECONDS:
            return cached[1]
    calendar_bytes = _fetch_calendar_bytes(
        source_url, username, secret, mode, auth_mode, start, end
    )
    events = _parse_events(calendar_bytes, start, end)
    with _cache_lock:
        _cache.clear()
        _cache[key] = (now, events)
    return events


def _event_dates(event, grid_start, grid_end):
    first = event.start.date() if isinstance(event.start, datetime) else event.start
    end_value = event.end.date() if isinstance(event.end, datetime) else event.end
    if event.all_day and end_value > first:
        end_value -= timedelta(days=1)
    if end_value < first:
        end_value = first
    current = max(first, grid_start)
    last = min(end_value, grid_end - timedelta(days=1))
    while current <= last:
        yield current
        current += timedelta(days=1)


def load_month(month_value=None):
    """Load one display month and return calendar cells for the Flask template."""
    month_start = _month_start(month_value)
    month_end = _shift_month(month_start, 1)
    calendar_weeks = calendar.Calendar(firstweekday=0).monthdatescalendar(
        month_start.year, month_start.month
    )
    grid_start = calendar_weeks[0][0]
    grid_end = calendar_weeks[-1][-1] + timedelta(days=1)
    events = _cached_events(grid_start, grid_end)
    events_by_date = {}
    for event in events:
        for event_date in _event_dates(event, grid_start, grid_end):
            events_by_date.setdefault(event_date, []).append(event)

    today = datetime.now(_timezone()).date()
    weeks = tuple(
        tuple(
            CalendarDay(
                value=day,
                in_month=day.month == month_start.month,
                is_today=day == today,
                events=tuple(events_by_date.get(day, ())),
            )
            for day in week
        )
        for week in calendar_weeks
    )
    return CalendarMonth(
        title=month_start.strftime("%B %Y"),
        month_key=month_start.strftime("%Y-%m"),
        previous_month=_shift_month(month_start, -1).strftime("%Y-%m"),
        next_month=month_end.strftime("%Y-%m"),
        weeks=weeks,
        event_count=len(events),
        source_url=os.getenv("CONFLUENCE_CALENDAR_WEB_URL", DEFAULT_WEB_URL),
    )


def clear_cache():
    """Clear cached calendar data for tests or administrative refreshes."""
    with _cache_lock:
        _cache.clear()
