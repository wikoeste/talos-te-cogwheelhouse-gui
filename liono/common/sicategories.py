"""Read SI-category expiration times from Confluence for the WBRS feed view."""

import csv
import os
import threading
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)

DEFAULT_API_URL = (
    "https://confluence.vrt.sourcefire.com/rest/api/content/161428515"
)
DEFAULT_PAGE_URL = (
    "https://confluence.vrt.sourcefire.com/spaces/TET/pages/161428515/"
    "SI+Category+Details"
)
DEFAULT_ALLOWED_HOST = "confluence.vrt.sourcefire.com"
HTTP_TIMEOUT = (5, 30)
CACHE_SECONDS = 3600
MAX_PAGE_BYTES = 2_000_000


class SICategoryConfigurationError(RuntimeError):
    """Raised when SI-category API configuration is missing or unsafe."""


class SICategoryFetchError(RuntimeError):
    """Raised when the SI-category table cannot be loaded or parsed."""


class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables = []
        self._table = None
        self._row = None
        self._cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._table = []
        elif self._table is not None and tag == "tr":
            self._row = []
        elif self._row is not None and tag in {"th", "td"}:
            self._cell = []

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        if tag in {"th", "td"} and self._cell is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None


_http = requests.Session()
_http.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )
    ),
)
_cache = None
_cache_time = 0.0
_cache_lock = threading.Lock()


def _configuration():
    api_url = os.getenv("CONFLUENCE_SI_CATEGORY_API_URL", DEFAULT_API_URL).strip()
    token = os.getenv("CONFLUENCE_CALENDAR_API_TOKEN", "").strip()
    allowed_host = os.getenv(
        "CONFLUENCE_CALENDAR_ALLOWED_HOST", DEFAULT_ALLOWED_HOST
    ).strip().lower()

    if not token:
        raise SICategoryConfigurationError(
            "CONFLUENCE_CALENDAR_API_TOKEN is required for SI-category expirations."
        )
    parsed = urlparse(api_url)
    if parsed.scheme != "https" or parsed.hostname != allowed_host:
        raise SICategoryConfigurationError(
            f"CONFLUENCE_SI_CATEGORY_API_URL must use HTTPS on {allowed_host}."
        )
    if parsed.username or parsed.password:
        raise SICategoryConfigurationError("Do not place Confluence credentials in the URL.")
    return api_url, token


def _parse_expirations(storage_html):
    parser = _TableParser()
    parser.feed(storage_html)
    required = {"feeds mapping category", "expiration time"}

    for table in parser.tables:
        if not table:
            continue
        normalized_headers = [header.casefold() for header in table[0]]
        if not required.issubset(normalized_headers):
            continue
        category_index = normalized_headers.index("feeds mapping category")
        expiration_index = normalized_headers.index("expiration time")
        expirations = {}
        for row in table[1:]:
            if len(row) <= max(category_index, expiration_index):
                continue
            category = row[category_index].strip().casefold()
            expiration = row[expiration_index].strip() or "Unknown"
            # The feeds file only supplies the mapping category, not the more
            # specific SI category. Keep the first matching Confluence row so
            # every mnemonic receives one deterministic expiration value.
            if category and category not in expirations:
                expirations[category] = expiration
        return expirations

    raise SICategoryFetchError(
        "Confluence did not return the expected SI Category expiration table."
    )


def _fetch_expirations():
    api_url, token = _configuration()
    try:
        response = _http.get(
            api_url,
            params={"expand": "body.storage,version"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        if response.status_code == 401:
            raise SICategoryFetchError(
                "Confluence rejected the SI-category API token (HTTP 401)."
            )
        if response.status_code == 403:
            raise SICategoryFetchError(
                "Confluence denied access to the SI Category Details page (HTTP 403)."
            )
        response.raise_for_status()
        if len(response.content) > MAX_PAGE_BYTES:
            raise SICategoryFetchError("The SI-category API response exceeded 2 MB.")
        payload = response.json()
        storage_html = payload["body"]["storage"]["value"]
        return _parse_expirations(storage_html)
    except SICategoryFetchError:
        raise
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise SICategoryFetchError(
            "Unable to retrieve SI-category expiration times from Confluence."
        ) from exc


def load_expirations():
    """Return expiration mappings and an optional stale-cache warning."""
    global _cache, _cache_time
    now = time.monotonic()
    with _cache_lock:
        if _cache is not None and now - _cache_time < CACHE_SECONDS:
            return dict(_cache), None

    try:
        expirations = _fetch_expirations()
    except SICategoryFetchError as exc:
        with _cache_lock:
            if _cache is not None:
                return dict(_cache), f"{exc} Showing cached expiration values."
        raise

    with _cache_lock:
        _cache = dict(expirations)
        _cache_time = now
    return expirations, None


def load_feed_rows(csv_path, expirations):
    """Load WBRS rows and attach one expiration mapped to each mnemonic."""
    with open(csv_path, newline="", encoding="utf-8-sig") as source:
        rows = list(csv.DictReader(source))
    for row in rows:
        mnemonic = (row.get("threat_mnemonic") or "").strip().casefold()
        row["expiration_time"] = expirations.get(mnemonic, "Unknown")
    return rows


def clear_cache():
    global _cache, _cache_time
    with _cache_lock:
        _cache = None
        _cache_time = 0.0
