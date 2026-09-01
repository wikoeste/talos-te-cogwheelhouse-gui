"""Fetch, validate, rank, and cache public threat-intelligence indicators."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = PROJECT_ROOT / ".malicious_top100.json"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 15
TOP_LIMIT = 100
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REFRESH_LOCK = threading.Lock()
MIN_REFRESH_INTERVAL_SECONDS = 60
LAST_REFRESH_AT = 0.0


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    kinds: tuple
    parser: str
    weight: int
    homepage: str


SOURCES = (
    Source("OpenPhish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", ("urls",), "lines", 90, "https://openphish.com/"),
    Source("Phishing.Database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt", ("urls",), "lines", 78, "https://github.com/Phishing-Database/Phishing.Database"),
    Source("ThreatFox", "https://threatfox.abuse.ch/export/csv/recent/", ("urls", "ips"), "threatfox", 94, "https://threatfox.abuse.ch/"),
    Source("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", ("ips",), "lines", 96, "https://feodotracker.abuse.ch/blocklist/"),
    Source("Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", ("ips",), "lines", 82, "https://rules.emergingthreats.net/"),
    Source("IPsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", ("ips",), "ipsum", 72, "https://github.com/stamparm/ipsum"),
    Source("MalwareBazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/", ("hashes",), "lines", 96, "https://bazaar.abuse.ch/"),
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so fixed feed URLs cannot become an SSRF pivot."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_text(source: Source) -> str:
    parsed = urlsplit(source.url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("feed URL must use HTTPS")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
    )
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "MaliciousTop100/1.0 (+local threat research dashboard)"},
        method="GET",
    )
    with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        content_type = response.headers.get_content_type()
        if content_type not in {"text/plain", "text/csv", "application/octet-stream"}:
            raise ValueError(f"unexpected content type: {content_type}")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ValueError("feed exceeded size limit")
    return payload.decode("utf-8", errors="replace")


def valid_public_ip(value: str) -> Optional[str]:
    candidate = value.strip().strip('"')
    if candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if address.version != 4 or not address.is_global:
        return None
    return str(address)


def valid_url(value: str) -> Optional[str]:
    candidate = value.strip().strip('"')
    if len(candidate) > 2048 or any(ch in candidate for ch in "\r\n\t"):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        host = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if host in {"localhost"} or host.endswith(".local"):
        return None
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        if not address.is_global:
            return None
    except ValueError:
        pass
    return candidate


def add_observation(store, kind: str, value: str, source: Source, position: int,
                    confidence: int = 70, seen: str = "", threat: str = "") -> bool:
    normalized = None
    if kind == "urls":
        normalized = valid_url(value)
    elif kind == "ips":
        normalized = valid_public_ip(value)
    elif kind == "hashes" and SHA256_RE.fullmatch(value.strip()):
        normalized = value.strip().lower()
    if not normalized:
        return False

    record = store[kind].setdefault(normalized, {
        "value": normalized, "sources": set(), "confidence": 0,
        "first_seen": "", "threat": set(), "position_score": 0,
    })
    record["sources"].add(source.name)
    record["confidence"] = max(record["confidence"], max(0, min(confidence, 100)))
    record["position_score"] = max(record["position_score"], max(0, 30 - position // 20))
    if seen and (not record["first_seen"] or seen > record["first_seen"]):
        record["first_seen"] = seen
    if threat:
        record["threat"].add(threat)
    return True


def parse_lines(text: str, source: Source, store) -> int:
    count = 0
    for position, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for kind in source.kinds:
            count += int(add_observation(store, kind, line.split()[0], source, position))
    return count


def parse_ipsum(text: str, source: Source, store) -> int:
    count = 0
    for position, raw in enumerate(text.splitlines()):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split()
        if not fields:
            continue
        confidence = min(100, 45 + (int(fields[1]) * 8 if len(fields) > 1 and fields[1].isdigit() else 0))
        count += int(add_observation(store, "ips", fields[0], source, position, confidence=confidence,
                                    threat="multi-feed suspicious activity"))
    return count


def parse_threatfox(text: str, source: Source, store) -> int:
    rows = (line for line in text.splitlines() if line and not line.startswith("#"))
    count = 0
    for position, row in enumerate(csv.reader(rows, skipinitialspace=True)):
        if len(row) < 10:
            continue
        seen, value, ioc_type = row[0].strip(), row[2].strip(), row[3].strip()
        threat = f"{row[4].strip()} · {row[7].strip()}".strip(" ·")
        confidence = int(row[9].strip()) if row[9].strip().isdigit() else 70
        kind = "urls" if ioc_type == "url" else "ips" if ioc_type in {"ip", "ip:port"} else ""
        if kind:
            count += int(add_observation(store, kind, value, source, position, confidence, seen, threat))
    return count


PARSERS = {"lines": parse_lines, "ipsum": parse_ipsum, "threatfox": parse_threatfox}


def rank_store(store) -> Dict[str, List[dict]]:
    result = {}
    for kind in ("urls", "ips", "hashes"):
        ranked = []
        for record in store[kind].values():
            source_weight = max(s.weight for s in SOURCES if s.name in record["sources"])
            overlap = min(30, (len(record["sources"]) - 1) * 15)
            score = min(100, round(source_weight * 0.58 + record["confidence"] * 0.28 + overlap + record["position_score"] * 0.14))
            ranked.append({
                "value": record["value"],
                "score": score,
                "confidence": record["confidence"],
                "sources": sorted(record["sources"]),
                "first_seen": record["first_seen"],
                "threat": ", ".join(sorted(record["threat"])) or "public threat feed listing",
            })
        ranked.sort(key=lambda item: (-item["score"], item["value"]))
        for index, item in enumerate(ranked[:TOP_LIMIT], 1):
            item["rank"] = index
        result[kind] = ranked[:TOP_LIMIT]
    return result


def refresh() -> dict:
    global LAST_REFRESH_AT
    with REFRESH_LOCK:
        now = time.monotonic()
        if CACHE_PATH.is_file() and now - LAST_REFRESH_AT < MIN_REFRESH_INTERVAL_SECONDS:
            return load_cache()
        store = {kind: {} for kind in ("urls", "ips", "hashes")}
        statuses = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_text, source): source for source in SOURCES}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    text = future.result()
                    count = PARSERS[source.parser](text, source, store)
                    statuses.append({"name": source.name, "status": "ok", "items": count, "homepage": source.homepage})
                except Exception:  # external feeds are independently fallible
                    statuses.append({"name": source.name, "status": "error", "items": 0,
                                     "homepage": source.homepage, "error": "feed unavailable"})

        if not any(item["status"] == "ok" for item in statuses) and CACHE_PATH.is_file():
            return load_cache()

        ranked = rank_store(store)
        payload = {
            "generated_at": utc_now(),
            "methodology": "Composite score from publisher weight, feed confidence, cross-source overlap, recency metadata, and feed order.",
            "counts": {kind: len(items) for kind, items in ranked.items()},
            "sources": sorted(statuses, key=lambda item: item["name"].lower()),
            "indicators": ranked,
        }
        temporary = CACHE_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary, CACHE_PATH)
        LAST_REFRESH_AT = now
        return payload


def load_cache() -> dict:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "generated_at": "", "methodology": "No cached data yet.",
            "counts": {"urls": 0, "ips": 0, "hashes": 0},
            "sources": [], "indicators": {"urls": [], "ips": [], "hashes": []},
        }
