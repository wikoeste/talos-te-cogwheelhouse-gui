"""Validated, web-friendly Juno Elasticsearch queries for the COG toolbox."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from liono.common import settings


MAX_RESULTS = 50
REQUEST_TIMEOUT = (3.05, 25)
ALLOWED_JUNO_HOSTS = {
    "prod-juno-search-api.sv4.ironport.com",
    "prod-juno-search-api.sco.cisco.com",
}
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{1,63}$")
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[A-Za-z0-9.-]{1,189}\.[A-Za-z]{2,63}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
CID_RE = re.compile(r"^[A-Za-z0-9_-]{1,160}$")


class ElasticQueryError(RuntimeError):
    """Base error with a message safe to render in the internal UI."""


class ElasticQueryValidationError(ElasticQueryError):
    """Raised when a form value does not meet the selected query contract."""


class ElasticQueryServiceError(ElasticQueryError):
    """Raised when Juno is unavailable or returns an invalid response."""


@dataclass(frozen=True)
class QuerySpec:
    key: str
    label: str
    description: str
    period: str
    placeholder: str
    input_type: str = "text"
    multiple: bool = False


QUERY_SPECS = (
    QuerySpec("submissions", "Plugin submissions", "Messages submitted by a CEC username.", "Last 24 hours", "CEC username"),
    QuerySpec("sha256", "Attachment SHA-256", "Messages containing an attachment hash.", "Last 6 months", "64-character SHA-256"),
    QuerySpec("domain_sdr", "Sender domain + SDR", "Messages and SDR verdicts associated with a sender domain.", "Last 3 months", "example.com"),
    QuerySpec("sender_email", "Sender email", "Messages from an exact sender address.", "Last 3 months", "sender@example.com", "email"),
    QuerySpec("sender_ip", "Sender IP", "Messages originating from an exact sender IP address.", "Last 3 months", "203.0.113.10"),
    QuerySpec("subject", "Message subject", "Messages matching an exact raw subject.", "Last 6 months", "Exact subject line"),
    QuerySpec("message_id", "Message-ID header", "Resolve raw Message-ID headers to CIDs.", "Last 6 months", "One Message-ID per line", multiple=True),
    QuerySpec("uri", "Message URI", "Messages containing one or more exact URIs.", "Last 6 months", "One http(s) URI per line", multiple=True),
    QuerySpec("recipient_domain", "Recipient domain", "Messages delivered to an exact receiving domain.", "Last 3 months", "example.com"),
    QuerySpec("recipient_email", "Recipient email", "Messages delivered to an exact recipient address.", "Last 3 months", "recipient@example.com", "email"),
    QuerySpec("guid", "Email ID / GUID", "Convert one or more Talos message GUIDs to CIDs.", "Last 6 months", "One UUID per line", multiple=True),
    QuerySpec("etd_verdict", "ETD verdict by CID", "Review ETD, SDR, and detection-engine verdicts for CIDs.", "Last 3 months", "One CID per line", multiple=True),
)
SPEC_BY_KEY = {spec.key: spec for spec in QUERY_SPECS}


RESULT_COLUMNS = {
    "submissions": (("cid", "CID"), ("timestamp", "Timestamp")),
    "sha256": (("cid", "CID"), ("timestamp", "Timestamp")),
    "domain_sdr": (("cid", "CID"), ("timestamp", "Timestamp"), ("sender", "Sender"), ("sender_ip", "Sender IP"), ("subject", "Subject"), ("sdr", "SDR verdict")),
    "sender_email": (("cid", "CID"), ("timestamp", "Timestamp"), ("category", "Category"), ("score", "Spam score"), ("subject", "Subject")),
    "sender_ip": (("cid", "CID"), ("timestamp", "Timestamp"), ("category", "Category"), ("score", "Spam score"), ("subject", "Subject")),
    "subject": (("cid", "CID"), ("timestamp", "Timestamp"), ("category", "Category"), ("score", "Spam score")),
    "message_id": (("cid", "CID"), ("timestamp", "Timestamp"), ("message_id", "Message-ID")),
    "uri": (("cid", "CID"), ("timestamp", "Timestamp"), ("subject", "Subject")),
    "recipient_domain": (("cid", "CID"), ("timestamp", "Timestamp"), ("recipient", "Recipient"), ("subject", "Subject")),
    "recipient_email": (("cid", "CID"), ("timestamp", "Timestamp"), ("recipient", "Recipient"), ("subject", "Subject")),
    "guid": (("cid", "CID"), ("timestamp", "Timestamp"), ("guid", "GUID")),
    "etd_verdict": (("cid", "CID"), ("timestamp", "Timestamp"), ("guid", "GUID"), ("etd", "ETD verdict"), ("sdr", "SDR verdict"), ("engines", "Detection engines")),
}


def public_specs() -> list[dict[str, Any]]:
    return [asdict(spec) for spec in QUERY_SPECS]


def _single(value: str, *, maximum: int = 512) -> str:
    normalized = (value or "").strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise ElasticQueryValidationError("Enter a valid search value within the displayed limit.")
    return normalized


def _multiple(value: str, validator) -> list[str]:
    values = []
    for raw in (value or "").splitlines():
        if raw.strip():
            candidate = validator(raw)
            if candidate not in values:
                values.append(candidate)
    if not values:
        raise ElasticQueryValidationError("Enter at least one search value.")
    if len(values) > 10:
        raise ElasticQueryValidationError("Submit no more than 10 values at once.")
    return values


def _username(value: str) -> str:
    candidate = _single(value, maximum=64)
    if not USERNAME_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("Enter a valid CEC username.")
    return f"{candidate.lower()}@cisco.com"


def _sha256(value: str) -> str:
    candidate = _single(value, maximum=64)
    if not SHA256_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("SHA-256 must contain exactly 64 hexadecimal characters.")
    return candidate.lower()


def _domain(value: str) -> str:
    candidate = _single(value, maximum=253).rstrip(".").lower()
    if not DOMAIN_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("Enter a fully qualified domain name such as example.com.")
    return candidate


def _email(value: str) -> str:
    candidate = _single(value, maximum=254).lower()
    if not EMAIL_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("Enter a valid full email address.")
    return candidate


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(_single(value, maximum=45)))
    except ValueError as exc:
        raise ElasticQueryValidationError("Enter a valid IPv4 or IPv6 address.") from exc


def _subject(value: str) -> str:
    return _single(value, maximum=300)


def _message_id(value: str) -> str:
    candidate = _single(value, maximum=512).removeprefix("<").removesuffix(">")
    if not candidate or any(char in candidate for char in "*?\\"):
        raise ElasticQueryValidationError("Message-ID values cannot contain wildcard characters.")
    return candidate


def _uri(value: str) -> str:
    candidate = _single(value, maximum=2048)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ElasticQueryValidationError("Each URI must be a complete http:// or https:// address.")
    return candidate


def _guid(value: str) -> str:
    candidate = _single(value, maximum=36)
    if not GUID_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("Each GUID must be a valid UUID.")
    return candidate.lower()


def _cid(value: str) -> str:
    candidate = _single(value, maximum=160)
    if not CID_RE.fullmatch(candidate):
        raise ElasticQueryValidationError("Each CID may contain only letters, numbers, underscores, and hyphens.")
    return candidate


def validate_search(query_type: str, raw_value: str):
    if query_type not in SPEC_BY_KEY:
        raise ElasticQueryValidationError("Select a supported Elastic query type.")
    validators = {
        "submissions": _username,
        "sha256": _sha256,
        "domain_sdr": _domain,
        "sender_email": _email,
        "sender_ip": _ip,
        "subject": _subject,
        "message_id": lambda value: _multiple(value, _message_id),
        "uri": lambda value: _multiple(value, _uri),
        "recipient_domain": _domain,
        "recipient_email": _email,
        "guid": lambda value: _multiple(value, _guid),
        "etd_verdict": lambda value: _multiple(value, _cid),
    }
    return validators[query_type](raw_value)


def _terms(path: str, field: str, values: list[str]) -> dict[str, Any]:
    clauses = [{"nested": {"path": path, "query": {"term": {field: value}}}} for value in values]
    return clauses[0] if len(clauses) == 1 else {"bool": {"should": clauses, "minimum_should_match": 1}}


def build_query(query_type: str, value) -> tuple[str, dict[str, Any]]:
    source_fields = [
        "@timestamp", "add_timestamp", "category", "ipas.ingest.spam_score", "message_id",
        "message_id_header.raw", "subject", "sender.address_raw", "sender_ip", "froms.address_raw",
        "tos.address_raw", "talos_msg_guid", "taln_ingest_result.message_guid", "sdr.verdict_name",
        "etd.etd_verdict", "etd.verdict_keywords",
    ]
    index = "juno_past_3_months"
    size = 20
    if query_type == "submissions":
        index = "juno_past_1_month"
        query = {"bool": {"must": [{"term": {"reporter.address_raw": value}}, {"range": {"@timestamp": {"gte": "now-24h"}}}]}}
    elif query_type == "sha256":
        index = "juno_past_6_months"
        query = {"nested": {"path": "attachments", "query": {"term": {"attachments.sha256": value}}}}
    elif query_type == "domain_sdr":
        query = {"nested": {"path": "froms", "query": {"term": {"froms.address_domain": value}}}}
    elif query_type == "sender_email":
        query = {"nested": {"path": "froms", "query": {"term": {"froms.address_raw": value}}}}
    elif query_type == "sender_ip":
        query = {"term": {"sender_ip": value}}
    elif query_type == "subject":
        index = "juno_past_6_months"
        query = {"term": {"subject.raw": value}}
    elif query_type == "message_id":
        index = "juno_past_6_months"
        clauses = []
        for item in value:
            clauses.extend((
                {"term": {"message_id_header.raw": item}},
                {"term": {"message_id_header.raw": f"<{item}>"}},
            ))
        query = {"bool": {"should": clauses, "minimum_should_match": 1}}
    elif query_type == "uri":
        index = "juno_past_6_months"
        query = _terms("uris", "uris.uri_raw", value)
    elif query_type == "recipient_domain":
        query = {"nested": {"path": "tos", "query": {"term": {"tos.address_domain": value}}}}
    elif query_type == "recipient_email":
        query = {"nested": {"path": "tos", "query": {"term": {"tos.address_raw": value}}}}
    elif query_type == "guid":
        index = "juno_past_6_months"
        clauses = [{"term": {"taln_ingest_result.message_guid": item}} for item in value]
        query = {"bool": {"should": clauses, "minimum_should_match": 1}}
    else:
        clauses = [{"term": {"_id": item}} for item in value]
        query = {"bool": {"should": clauses, "minimum_should_match": 1}}
    return index, {"size": size, "track_total_hits": True, "_source": source_fields, "query": query}


def _first(value: Any, *keys: str) -> str:
    current = value
    for key in keys:
        if isinstance(current, list):
            current = current[0] if current else ""
        if not isinstance(current, dict):
            return ""
        current = current.get(key, "")
    if isinstance(current, list):
        current = current[0] if current else ""
    return str(current) if current not in (None, "") else ""


def _row(hit: dict[str, Any]) -> dict[str, str]:
    source = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    engine_values = _first(source, "etd", "verdict_keywords")
    if isinstance(source.get("etd", {}).get("verdict_keywords") if isinstance(source.get("etd"), dict) else None, dict):
        engines = source["etd"]["verdict_keywords"]
        engine_values = " · ".join(f"{key}: {value}" for key, value in sorted(engines.items()) if value not in (None, ""))
    score = _first(source, "ipas", "ingest", "spam_score") or _first(source, "ipas.ingest.spam_score")
    return {
        "cid": str(hit.get("_id", "")),
        "timestamp": _first(source, "@timestamp") or _first(source, "add_timestamp"),
        "category": _first(source, "category"),
        "score": score,
        "sender": _first(source, "sender", "address_raw") or _first(source, "froms", "address_raw"),
        "sender_ip": _first(source, "sender_ip"),
        "recipient": _first(source, "tos", "address_raw"),
        "subject": _first(source, "subject"),
        "message_id": _first(source, "message_id_header", "raw") or _first(source, "message_id"),
        "guid": _first(source, "talos_msg_guid") or _first(source, "taln_ingest_result", "message_guid"),
        "sdr": _first(source, "sdr", "verdict_name"),
        "etd": _first(source, "etd", "etd_verdict"),
        "engines": engine_values,
    }


def _endpoint(index: str) -> str:
    base = str(settings.juno).rstrip("/") + "/"
    parsed = urlsplit(base)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_JUNO_HOSTS:
        raise ElasticQueryServiceError("The configured Juno endpoint is not approved.")
    return f"{base}{index}/_search"


def search(query_type: str, raw_value: str) -> dict[str, Any]:
    value = validate_search(query_type, raw_value)
    if not getattr(settings, "junoKey", None):
        raise ElasticQueryServiceError("The Jupiter API key is not configured for this account.")
    index, body = build_query(query_type, value)
    try:
        response = requests.get(
            _endpoint(index),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=body,
            auth=(settings.uname, settings.junoKey),
            timeout=REQUEST_TIMEOUT,
            verify=True,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.Timeout as exc:
        raise ElasticQueryServiceError("Juno timed out before returning results.") from exc
    except (requests.RequestException, ValueError) as exc:
        raise ElasticQueryServiceError("Juno could not complete the search.") from exc
    hits_container = payload.get("hits") if isinstance(payload, dict) else None
    if not isinstance(hits_container, dict) or not isinstance(hits_container.get("hits"), list):
        raise ElasticQueryServiceError("Juno returned an unexpected response format.")
    total_value = hits_container.get("total", 0)
    total = total_value.get("value", 0) if isinstance(total_value, dict) else total_value
    rows = [_row(hit) for hit in hits_container["hits"][:MAX_RESULTS] if isinstance(hit, dict)]
    spec = SPEC_BY_KEY[query_type]
    display_value = ", ".join(value) if isinstance(value, list) else value
    return {
        "query_type": query_type,
        "label": spec.label,
        "period": spec.period,
        "search_value": display_value,
        "total": int(total) if isinstance(total, int) else len(rows),
        "rows": rows,
        "columns": [{"key": key, "label": label} for key, label in RESULT_COLUMNS[query_type]],
    }
