"""Validated web queries matching the talos-te-bpsearch menu."""

import os
import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)


GUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
BP_SIG_PATTERN = re.compile(r"^\d{14}$")
DAY_OPTIONS = OrderedDict((("1", "24 hours"), ("7", "7 days"), ("14", "14 days"), ("30", "30 days"), ("90", "90 days")))

MENU_OPTIONS = OrderedDict((
    ("signature", {
        "group": "Signature files",
        "label": "BP Sig Search",
        "description": "Search active and retired signatures by name, SigID, MITRE tactic, CVE, or text.",
        "fields": ("query",),
    }),
    ("cloud_ioc", {
        "group": "Cloud IOC",
        "label": "Cloud IOC Sig Search",
        "description": "Search Secure Endpoint Cloud IOC definitions by name or GUID.",
        "fields": ("query",),
    }),
    ("bpfps", {
        "group": "MOAEC queries",
        "label": "BP False Positives",
        "description": "Find BP events for a company and behavioral-protection signature.",
        "fields": ("business_guid", "bp_sig_id", "days"),
    }),
    ("cloud_ioc_events", {
        "group": "MOAEC queries",
        "label": "Cloud IOC Events",
        "description": "Find OPEN_IOC events for a Secure Endpoint connector.",
        "fields": ("agent_guid", "days"),
    }),
    ("connector_errors", {
        "group": "MOAEC queries",
        "label": "SE Connector Errors",
        "description": "Find product update, policy, download, and signature-load failures.",
        "fields": ("business_guid", "days"),
    }),
    ("sha_or_sig", {
        "group": "MOAEC queries",
        "label": "SHA256 or BP SigID",
        "description": "Find events matching either a SHA256 or BP signature ID.",
        "fields": ("sha256", "bp_sig_id", "days"),
    }),
    ("sha256", {
        "group": "MOAEC queries",
        "label": "SHA256 Only",
        "description": "Search the previous 14 days for a SHA256.",
        "fields": ("sha256",),
    }),
    ("connector_events", {
        "group": "MOAEC queries",
        "label": "SE Connector Events",
        "description": "Find recent event telemetry for one endpoint connector GUID.",
        "fields": ("agent_guid", "days"),
    }),
    ("company_guid", {
        "group": "MOAEC queries",
        "label": "Company Name to GUID",
        "description": "Resolve a company name to Secure Endpoint business GUIDs.",
        "fields": ("company_name",),
    }),
))

RESULT_COLUMNS = (
    ("timestamp", "Timestamp"),
    ("event_type", "Event"),
    ("name", "Name"),
    ("signature_id", "BP SigID"),
    ("sha256", "SHA256"),
    ("business_guid", "Business GUID"),
    ("agent_guid", "Agent GUID"),
)


class BPSearchError(RuntimeError):
    """Raised when a BP Search request is invalid or unavailable."""


def menu_options():
    return MENU_OPTIONS


def _required(values, key, label, maximum=200):
    value = str(values.get(key, "") or "").strip()
    if not value or len(value) > maximum:
        raise BPSearchError("Enter a valid {}.".format(label))
    return value


def _guid(values, key, label):
    value = _required(values, key, label, 36)
    if not GUID_PATTERN.fullmatch(value):
        raise BPSearchError("Enter a valid {}.".format(label))
    return value.lower()


def _sha256(values):
    value = _required(values, "sha256", "SHA256", 64)
    if not SHA256_PATTERN.fullmatch(value):
        raise BPSearchError("Enter a valid 64-character SHA256.")
    return value.lower()


def _bp_sig(values):
    value = _required(values, "bp_sig_id", "14-digit BP signature ID", 14)
    if not BP_SIG_PATTERN.fullmatch(value):
        raise BPSearchError("Enter a valid 14-digit BP signature ID.")
    return value


def _days(values, default="7"):
    value = str(values.get("days", default))
    if value not in DAY_OPTIONS:
        raise BPSearchError("Select a supported search period.")
    return int(value)


def _endpoint(environment_name, suffix=""):
    configured = os.getenv(environment_name, "").strip()
    if not configured:
        raise BPSearchError("{} is not configured for BP Search.".format(environment_name))
    parsed = urlparse(configured)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BPSearchError("{} must be a credential-free HTTPS URL.".format(environment_name))
    return urljoin(configured.rstrip("/") + "/", suffix.lstrip("/"))


def _credentials():
    username = os.getenv("BPSEARCH_MOAEC_USERNAME", "").strip()
    password = os.getenv("BPSEARCH_MOAEC_PASSWORD", "")
    if not username or not password:
        raise BPSearchError("MOAEC credentials are not configured for BP Search.")
    return username, password


def _window(days):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return (
        start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )


def _value(fields, *keys):
    for key in keys:
        value = fields.get(key)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value not in (None, ""):
            return str(value)
    return ""


def _normalize_hit(hit):
    fields = hit.get("fields") if isinstance(hit, dict) else {}
    fields = fields if isinstance(fields, dict) else {}
    source = hit.get("_source") if isinstance(hit, dict) else {}
    source = source if isinstance(source, dict) else {}
    return {
        "timestamp": _value(fields, "client_timestamp", "timestamp") or str(source.get("timestamp", "")),
        "event_type": _value(fields, "event_type.keyword", "event_type") or str(source.get("event_type", "")),
        "name": _value(fields, "data.name", "data.short_description", "data.file.name"),
        "signature_id": _value(fields, "data.details.sig_id"),
        "sha256": _value(fields, "data.file.sha256", "data.observables.file.sha256", "data.parent.file.sha256"),
        "business_guid": _value(fields, "business_guid"),
        "agent_guid": _value(fields, "agent_guid"),
    }


def _moaec_filters(option, values):
    days = 14 if option == "sha256" else _days(values)
    start, end = _window(days)
    filters = [{"range": {"timestamp": {"format": "strict_date_optional_time", "gte": start, "lte": end}}}]
    summary = "{} day search".format(days)
    if option == "bpfps":
        guid, signature = _guid(values, "business_guid", "business GUID"), _bp_sig(values)
        filters[:0] = [{"match_phrase": {"business_guid": guid}}, {"match_phrase": {"data.details.sig_id": signature}}]
        summary = "Business {} · BP SigID {} · {}".format(guid, signature, summary)
    elif option == "cloud_ioc_events":
        guid = _guid(values, "agent_guid", "agent GUID")
        filters[:0] = [{"match_phrase": {"agent_guid": guid}}, {"match_phrase": {"event_type": "OPEN_IOC"}}]
        summary = "Agent {} · {}".format(guid, summary)
    elif option == "connector_errors":
        guid = _guid(values, "business_guid", "business GUID")
        filters[:0] = [
            {"match_phrase": {"business_guid": guid}},
            {"bool": {"should": [
                {"match_phrase": {"event_type": event}}
                for event in (
                    "PRODUCT_UPDATE_FAILED",
                    "IMN_J_EVENT_PACKAGE_MANAGER_DOWNLOAD_FAILED",
                    "POLICY_FETCH_FAILED",
                    "IMN_J_EVENT_PACKAGE_MANAGER_SIGNATURE_LOAD_FAILED",
                )
            ], "minimum_should_match": 1}},
        ]
        summary = "Business {} · {}".format(guid, summary)
    elif option == "sha_or_sig":
        sha256, signature = _sha256(values), _bp_sig(values)
        filters.insert(0, {"bool": {"should": [
            {"match_phrase": {"data.file.sha256": sha256}},
            {"match_phrase": {"data.details.sig_id": signature}},
        ], "minimum_should_match": 1}})
        summary = "SHA256 {}… · BP SigID {} · {}".format(sha256[:12], signature, summary)
    elif option == "sha256":
        sha256 = _sha256(values)
        filters.insert(0, {"match_phrase": {"data.file.sha256": sha256}})
        summary = "SHA256 {}… · {}".format(sha256[:12], summary)
    elif option == "connector_events":
        guid = _guid(values, "agent_guid", "agent GUID")
        filters.insert(0, {"match_phrase": {"agent_guid": guid}})
        summary = "Agent {} · {}".format(guid, summary)
    else:
        raise BPSearchError("Unsupported MOAEC query option.")
    return filters, summary


def _search_moaec(option, values):
    filters, summary = _moaec_filters(option, values)
    payload = {
        "track_total_hits": True,
        "fields": [{"field": "*", "include_unmapped": True}],
        "size": 100,
        "_source": False,
        "query": {"bool": {"filter": filters}},
    }
    try:
        response = requests.post(
            _endpoint("BPSEARCH_MOAEC_URL", "amp-events-*/_search"),
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
            json=payload,
            auth=_credentials(),
            timeout=(5, 30),
        )
        response.raise_for_status()
        body = response.json()
        hits = body.get("hits", {})
        raw_rows = hits.get("hits", []) if isinstance(hits, dict) else []
        total_value = hits.get("total", len(raw_rows)) if isinstance(hits, dict) else len(raw_rows)
        total = total_value.get("value", len(raw_rows)) if isinstance(total_value, dict) else int(total_value)
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise BPSearchError("The MOAEC query could not be completed.") from exc
    return {
        "option": option,
        "label": MENU_OPTIONS[option]["label"],
        "summary": summary,
        "columns": RESULT_COLUMNS,
        "rows": [_normalize_hit(hit) for hit in raw_rows[:100]],
        "total": total,
    }


def _search_cloud_ioc(values):
    query = _required(values, "query", "IOC name or GUID", 200).casefold()
    authorization = os.getenv("BPSEARCH_CLOUD_IOC_AUTHORIZATION", "").strip()
    if not authorization:
        raise BPSearchError("Cloud IOC API authorization is not configured for BP Search.")
    url = _endpoint("BPSEARCH_CLOUD_IOC_URL", "indicators")
    records = []
    try:
        for _page in range(3):
            response = requests.get(
                url,
                headers={"Authorization": authorization, "Accept": "application/json"},
                timeout=(5, 30),
            )
            response.raise_for_status()
            body = response.json()
            records.extend(body.get("data", []))
            next_url = body.get("metadata", {}).get("links", {}).get("next")
            if not next_url:
                break
            if urlparse(next_url).netloc != urlparse(url).netloc or urlparse(next_url).scheme != "https":
                raise BPSearchError("Cloud IOC pagination returned an unapproved URL.")
            url = next_url
    except BPSearchError:
        raise
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise BPSearchError("The Cloud IOC query could not be completed.") from exc
    rows = [
        {
            "name": str(item.get("name", "")),
            "guid": str(item.get("guid", "")),
            "description": str(item.get("description", "")),
            "hits": item.get("observed_compromises", 0),
        }
        for item in records
        if query in str(item.get("name", "")).casefold() or query in str(item.get("guid", "")).casefold()
    ]
    return {
        "option": "cloud_ioc",
        "label": MENU_OPTIONS["cloud_ioc"]["label"],
        "summary": "Name or GUID contains: {}".format(query),
        "columns": (("name", "Name"), ("guid", "GUID"), ("description", "Description"), ("hits", "Observed compromises")),
        "rows": rows[:100],
        "total": len(rows),
    }


def _search_company(values):
    company = _required(values, "company_name", "company name", 150)
    api_key = os.getenv("BPSEARCH_INTEL_API_KEY", "").strip()
    if not api_key:
        raise BPSearchError("Intel API authorization is not configured for BP Search.")
    try:
        response = requests.get(
            _endpoint("BPSEARCH_INTEL_API_URL", "ntu/1/businessname"),
            params={"apikey": api_key, "name": company},
            headers={"Accept": "application/json"},
            timeout=(5, 15),
        )
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise BPSearchError("The company GUID lookup could not be completed.") from exc
    rows = [
        {
            "guid": str(item.get("guid", "")),
            "company": str(item.get("business", "")),
            "region": str(item.get("region", "Unknown")),
            "created": str(item.get("created", "")),
        }
        for item in body.get("businesses", [])
    ]
    return {
        "option": "company_guid",
        "label": MENU_OPTIONS["company_guid"]["label"],
        "summary": "Company name: {}".format(company),
        "columns": (("guid", "GUID"), ("company", "Company"), ("region", "Region"), ("created", "Created")),
        "rows": rows[:100],
        "total": len(rows),
    }


def search(option, values):
    if option not in MENU_OPTIONS or option == "signature":
        raise BPSearchError("Select a supported BP Search option.")
    if option == "cloud_ioc":
        return _search_cloud_ioc(values)
    if option == "company_guid":
        return _search_company(values)
    return _search_moaec(option, values)
