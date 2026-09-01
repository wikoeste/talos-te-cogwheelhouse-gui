"""Authenticated, bounded CVE lookups against the internal Analysis API."""

import json
import os
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)
API_URL = os.getenv(
    "CR_LOOKUP_URL",
    "https://analysis-api.vrt.sourcefire.com/vulnerability/cve",
)
REQUEST_TIMEOUT = (5, int(os.getenv("CR_LOOKUP_TIMEOUT_SECONDS", "20")))
MAX_RESPONSE_BYTES = int(os.getenv("CR_LOOKUP_MAX_RESPONSE_MB", "2")) * 1024 * 1024
MAX_BATCH_CVES = max(1, min(int(os.getenv("CR_LOOKUP_MAX_CVES", "25")), 50))
MAX_BATCH_WORKERS = max(1, min(int(os.getenv("CR_LOOKUP_WORKERS", "5")), 10))
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TICKET_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?P<project>RESBZ|COG|ACE)-(?P<number>\d+)(?![A-Z0-9])",
    re.IGNORECASE,
)
EXPLOIT_MARKERS = ("exploit", "proof of concept", "proof_of_concept", "poc")


class CRLookupError(RuntimeError):
    """Raised when a CR lookup cannot be completed safely."""


class CRValidationError(CRLookupError):
    """Raised when CVE input is invalid."""


def normalize_cve(value):
    cve = str(value or "").strip().upper()
    if not CVE_PATTERN.fullmatch(cve):
        raise CRValidationError("Enter a CVE in the format CVE-2026-63030.")
    return cve


def normalize_cves(value):
    candidates = [item for item in re.split(r"[\s,;]+", str(value or "").strip()) if item]
    if not candidates:
        raise CRValidationError("Enter at least one CVE identifier.")
    if len(candidates) > MAX_BATCH_CVES:
        raise CRValidationError("Enter no more than {} CVEs per lookup.".format(MAX_BATCH_CVES))
    normalized, invalid = [], []
    for candidate in candidates:
        try:
            cve = normalize_cve(candidate)
        except CRValidationError:
            invalid.append(candidate)
            continue
        if cve not in normalized:
            normalized.append(cve)
    if invalid:
        preview = ", ".join(invalid[:5])
        if len(invalid) > 5:
            preview += ", and {} more".format(len(invalid) - 5)
        raise CRValidationError("Invalid CVE identifier(s): {}.".format(preview))
    return normalized


def _api_key():
    key = os.getenv("ANALYSIS_API_KEY", "").strip()
    if key:
        return key
    try:
        profile_lines = (Path.home() / ".profile").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        profile_lines = []
    for line in profile_lines:
        candidate = line.strip()
        if candidate.startswith("export "):
            candidate = candidate[7:].lstrip()
        if not candidate.startswith("ANALYSIS_API_KEY="):
            continue
        try:
            assignments = shlex.split(candidate, comments=True, posix=True)
        except ValueError:
            assignments = []
        if assignments and assignments[0].startswith("ANALYSIS_API_KEY="):
            key = assignments[0].partition("=")[2].strip()
        break
    if not key:
        raise CRLookupError("ANALYSIS_API_KEY is not configured in the environment or ~/.profile.")
    return key


def _verified_api_url():
    parsed = urlsplit(API_URL)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CRLookupError("CR_LOOKUP_URL must be a credential-free HTTPS URL.")
    return API_URL


def lookup(cve, http=requests):
    normalized = normalize_cve(cve)
    ca_bundle = os.getenv("ANALYSIS_API_CA_BUNDLE", "").strip()
    verify = str(Path(ca_bundle).expanduser()) if ca_bundle else True
    if ca_bundle and not Path(verify).is_file():
        raise CRLookupError("ANALYSIS_API_CA_BUNDLE does not reference a readable file.")
    try:
        response = http.get(
            _verified_api_url(),
            params={"cve": normalized, "tickets": "true"},
            headers={"Accept": "application/json", "X-API-Key": _api_key()},
            timeout=REQUEST_TIMEOUT,
            verify=verify,
        )
    except requests.exceptions.SSLError as exc:
        raise CRLookupError(
            "Analysis API TLS validation failed. Configure ANALYSIS_API_CA_BUNDLE with the approved internal CA bundle."
        ) from exc
    except requests.Timeout as exc:
        raise CRLookupError("The Analysis API lookup timed out.") from exc
    except requests.RequestException as exc:
        raise CRLookupError("Unable to connect to the Analysis API.") from exc
    if response.status_code in {401, 403}:
        raise CRLookupError("The Analysis API rejected the configured API key.")
    if response.status_code == 404:
        raise CRLookupError("No Analysis API record was found for {}.".format(normalized))
    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise CRLookupError("The Analysis API returned HTTP {}.".format(response.status_code)) from exc
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise CRLookupError("The Analysis API response exceeded the safety limit.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise CRLookupError("The Analysis API returned invalid JSON data.") from exc
    if payload in (None, {}, []):
        raise CRLookupError("No Analysis API record was found for {}.".format(normalized))
    return normalized, payload


def lookup_many(cves):
    normalized = normalize_cves(cves) if isinstance(cves, str) else [normalize_cve(cve) for cve in cves]
    results = {}
    with ThreadPoolExecutor(max_workers=min(MAX_BATCH_WORKERS, len(normalized))) as executor:
        futures = {executor.submit(lookup, cve): cve for cve in normalized}
        for future in as_completed(futures):
            cve = futures[future]
            try:
                _, payload = future.result()
            except CRLookupError as exc:
                results[cve] = {"cve": cve, "error": str(exc), "payload": None}
            except Exception:
                results[cve] = {"cve": cve, "error": "An unexpected Analysis API error occurred.", "payload": None}
            else:
                results[cve] = {"cve": cve, "error": None, "payload": payload}
    return [results[cve] for cve in normalized]


def format_payload(payload):
    source = payload
    if isinstance(payload, dict):
        for key in ("data", "results", "vulnerabilities", "items"):
            if key in payload and isinstance(payload[key], (dict, list)):
                source = payload[key]
                break
    source_records = source if isinstance(source, list) else [source]
    records = []
    for item in source_records:
        fields = _flatten_html_fields(item) if isinstance(item, dict) else [("Result", str(item))]
        records.append({"fields": fields})
    return records


def _flatten_html_fields(value, prefix=""):
    fields = []
    if isinstance(value, dict):
        for name, child in value.items():
            label = str(name).replace("_", " ").title()
            path = "{} › {}".format(prefix, label) if prefix else label
            fields.extend(_flatten_html_fields(child, path))
    elif isinstance(value, list):
        if not value:
            fields.append((prefix or "Value", "Unknown"))
        elif all(not isinstance(item, (dict, list)) for item in value):
            fields.append((prefix or "Value", ", ".join(_display_scalar(item) for item in value)))
        else:
            for index, child in enumerate(value, start=1):
                fields.extend(_flatten_html_fields(child, "{} [{}]".format(prefix, index)))
    else:
        fields.append((prefix or "Value", _display_scalar(value)))
    return fields


def _display_scalar(value):
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def ticket_link_parts(value):
    text, parts, position = str(value), [], 0
    for match in TICKET_PATTERN.finditer(text):
        if match.start() > position:
            parts.append({"text": text[position:match.start()], "url": None})
        project, number = match.group("project").upper(), match.group("number")
        if project in {"RESBZ", "COG"}:
            url = "https://jira.talos.cisco.com/browse/{}-{}".format(project, number)
        else:
            url = "https://analyst-console.vrt.sourcefire.com/snort_escalations/{}".format(number)
        parts.append({"text": match.group(0), "url": url})
        position = match.end()
    if position < len(text):
        parts.append({"text": text[position:], "url": None})
    return parts or [{"text": text, "url": None}]


def _walk_payload(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (str(key),)
            yield child_path, child
            yield from _walk_payload(child, child_path)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_payload(child, path)


def extract_snort_sids(payload):
    sids = []
    for path, value in _walk_payload(payload):
        normalized_path = [component.casefold().replace("-", "_") for component in path]
        if "snort" not in normalized_path:
            continue
        field = normalized_path[-1] if normalized_path else ""
        if field not in {"sid", "sids", "signature", "signatures"}:
            continue
        serialized = value if isinstance(value, str) else json.dumps(value, default=str)
        for match in re.finditer(r"(?<!\d)(\d+)(?!\d)", serialized):
            sid = match.group(1)
            if int(sid) > 0 and sid not in sids:
                sids.append(sid)
    return sids


def _safe_urls(value):
    serialized = value if isinstance(value, str) else json.dumps(value, default=str)
    urls = []
    for match in URL_PATTERN.findall(serialized):
        candidate = match.rstrip(".,);]}")
        parsed = urlsplit(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            urls.append(candidate)
    return urls


def extract_research(payload):
    exploit_links, seen_urls, feasibility, signature_evidence = [], set(), None, False
    for path, value in _walk_payload(payload):
        normalized_path = " ".join(path).casefold().replace("-", "_")
        if any(marker in normalized_path for marker in EXPLOIT_MARKERS):
            for url in _safe_urls(value):
                if url not in seen_urls and len(exploit_links) < 50:
                    seen_urls.add(url)
                    exploit_links.append({"label": path[-1].replace("_", " ").title(), "url": url})
        compact_path = normalized_path.replace(" ", "_")
        explicit = any(marker in compact_path for marker in ("signature_feasib", "snort_feasib", "network_detection_feasib"))
        if explicit and feasibility is None and not isinstance(value, (dict, list)):
            if isinstance(value, bool):
                feasibility = "Yes" if value else "No"
            elif value is not None and str(value).strip():
                feasibility = str(value).strip()
        if "snort" in compact_path and any(marker in compact_path for marker in ("signature", "sid", "rule")) and value not in (None, "", [], {}, False):
            signature_evidence = True
    if feasibility:
        note = "Explicit feasibility value reported by the Analysis API."
    elif signature_evidence:
        feasibility = "Existing signature evidence reported"
        note = "The response references Snort signature data, but does not explicitly state whether a new signature is feasible."
    else:
        feasibility = "Unknown"
        note = "The Analysis API response did not provide explicit Snort feasibility or signature evidence."
    return {
        "exploit_links": exploit_links,
        "exploit_status": "Reported" if exploit_links else "No PoC or exploit link reported",
        "signature_feasibility": feasibility,
        "signature_note": note,
    }
