"""Bounded PCAP inspection and Snort content-option analysis."""

from __future__ import annotations

import ipaddress
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pyshark
import regex as pcre_regex


MAX_RULE_LENGTH = 64_000
MAX_PACKETS = 10_000
MAX_PACKET_ROWS = 250
MAX_MATCH_ROWS = 500
MAX_SUMMARY_ROWS = 50
SUMMARY_SECTION_PREFIX = "[[PIGREPLAY_SECTION]] "
SUMMARY_TITLE_PREFIX = "[[PIGREPLAY_TITLE]] "
PCRE_TIMEOUT_SECONDS = max(
    0.001, min(float(os.getenv("PCRE_MATCH_TIMEOUT_MS", "5")) / 1000, 0.1)
)


class AnalysisError(ValueError):
    """Raised when a capture or rule cannot be analyzed safely."""


def _split_options(value):
    options = []
    current = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quoted:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            option = "".join(current).strip()
            if option:
                options.append(option)
            current = []
        else:
            current.append(char)
    if quoted:
        raise AnalysisError("The Snort rule contains an unterminated content value.")
    option = "".join(current).strip()
    if option:
        options.append(option)
    return options


def _decode_content(value):
    output = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "|":
            end = value.find("|", index + 1)
            if end < 0:
                raise AnalysisError("A content hex block is missing its closing pipe.")
            tokens = value[index + 1 : end].split()
            try:
                output.extend(int(token, 16) for token in tokens if token)
            except ValueError as exc:
                raise AnalysisError("A content hex block contains invalid hexadecimal bytes.") from exc
            if any(len(token) != 2 for token in tokens):
                raise AnalysisError("Content hex bytes must use two hexadecimal digits.")
            index = end + 1
            continue
        if char == "\\" and index + 1 < len(value):
            index += 1
            char = value[index]
        output.extend(char.encode("utf-8"))
        index += 1
    if not output:
        raise AnalysisError("Empty content options are not supported.")
    return bytes(output)


CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}


def _modifier_parts(option):
    """Return a modifier name/value for Snort 2 ':' and Snort 3 space syntax."""
    name, separator, raw_value = option.partition(":")
    if separator:
        return name.strip().casefold(), raw_value.strip()
    parts = option.strip().split(None, 1)
    return parts[0].casefold(), parts[1].strip() if len(parts) == 2 else ""


def _apply_content_modifier(option, current, ignored_options):
    keyword, value = _modifier_parts(option)
    if keyword not in CONTENT_MODIFIERS:
        ignored_options.append(option.strip())
        return
    if current is None:
        ignored_options.append(option.strip())
        return
    if keyword == "nocase":
        current["nocase"] = True
        return
    try:
        current[keyword] = int(value)
    except ValueError as exc:
        raise AnalysisError(f"The {keyword} modifier must be an integer.") from exc


def _last_unescaped_slash(value):
    for index in range(len(value) - 1, 0, -1):
        if value[index] != "/":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and value[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return index
    return -1


def _end_only_pattern(pattern):
    """Translate unescaped PCRE '$' anchors to strict end-of-buffer anchors."""
    output = []
    escaped = False
    character_class = False
    for char in pattern:
        if escaped:
            output.extend(("\\", char))
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[":
            character_class = True
        elif char == "]" and character_class:
            character_class = False
        if char == "$" and not character_class:
            output.append(r"\Z")
        else:
            output.append(char)
    if escaped:
        output.append("\\")
    return "".join(output)


def _parse_pcre(value, index):
    quoted = re.fullmatch(r'(!?)\s*"((?:\\.|[^"\\])*)"', value, re.DOTALL)
    if not quoted:
        raise AnalysisError("Each pcre option must use a quoted /pattern/ value.")
    expression = quoted.group(2)
    if not expression.startswith("/"):
        raise AnalysisError("Each pcre expression must begin with a forward slash.")
    closing = _last_unescaped_slash(expression)
    if closing <= 0:
        raise AnalysisError("Each pcre expression must end with a forward slash.")
    pattern = expression[1:closing]
    flags_text = expression[closing + 1 :]
    unknown_flags = sorted(set(flags_text) - set("ismxAEGOR"))
    unsupported_flags = sorted(set(flags_text) & {"G"})
    reason = ""
    if unknown_flags:
        reason = "Unsupported Snort PCRE flag(s): " + ", ".join(unknown_flags)
    elif unsupported_flags:
        reason = "Unsupported Snort PCRE flag(s): " + ", ".join(unsupported_flags)
    compiled = None
    compile_flags = 0
    if "i" in flags_text:
        compile_flags |= pcre_regex.IGNORECASE
    if "s" in flags_text:
        compile_flags |= pcre_regex.DOTALL
    if "m" in flags_text:
        compile_flags |= pcre_regex.MULTILINE
    if "x" in flags_text:
        compile_flags |= pcre_regex.VERBOSE
    compiled_pattern = pattern
    if "A" in flags_text:
        compiled_pattern = r"\A(?:" + compiled_pattern + ")"
    if "E" in flags_text:
        compiled_pattern = _end_only_pattern(compiled_pattern)
    if not reason:
        try:
            compiled = pcre_regex.compile(compiled_pattern.encode("utf-8"), compile_flags)
        except (pcre_regex.error, UnicodeError) as exc:
            reason = f"PCRE is not compatible with the local analyzer: {exc}"
    return {
        "index": index,
        "source": pattern,
        "expression": expression,
        "flags": flags_text,
        "negated": bool(quoted.group(1)),
        "relative": "R" in flags_text,
        "supported": compiled is not None,
        "unsupported_reason": reason,
        "_compiled": compiled,
    }


def parse_rule(rule_text):
    """Parse the Snort header and content options used by the inspector."""
    rule = str(rule_text or "")
    if len(rule) > MAX_RULE_LENGTH:
        raise AnalysisError("The Snort rule exceeds the 64,000-character limit.")
    # Rules copied from configuration files often use a trailing backslash to
    # continue on the next line. Treat that sequence as ordinary whitespace.
    rule = re.sub(r"\\[ \t]*(?:\r?\n|$)", " ", rule).strip()
    if not rule:
        raise AnalysisError("Enter a Snort rule to analyze.")
    match = re.fullmatch(
        r"\s*(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*",
        rule,
        re.DOTALL,
    )
    service_header = False
    if match:
        action, protocol, source_net, source_port, direction, destination_net, destination_port, body = match.groups()
    else:
        service_match = re.fullmatch(
            r"\s*(\w+)\s+(\w+)\s*\((.*)\)\s*", rule, re.DOTALL
        )
        if not service_match:
            raise AnalysisError("Enter a complete Snort rule with a header and parenthesized options.")
        action, protocol, body = service_match.groups()
        source_net = source_port = destination_net = destination_port = "any"
        direction = "->"
        service_header = True
    contents = []
    pcres = []
    payload_checks = []
    ignored_options = [f"service header: {protocol}"] if service_header else []
    message = ""
    sid = ""
    current = None
    for option in _split_options(body):
        name, separator, raw_value = option.partition(":")
        keyword = name.strip().casefold()
        value = raw_value.strip() if separator else ""
        if keyword == "content":
            content_match = re.fullmatch(
                r'(!?)\s*"((?:\\.|[^"\\])*)"\s*(?:,\s*(.*))?',
                value,
                re.DOTALL,
            )
            if not content_match:
                raise AnalysisError("Each content option must use a quoted value.")
            current = {
                "index": len(contents) + 1,
                "value": _decode_content(content_match.group(2)),
                "source": content_match.group(2),
                "negated": bool(content_match.group(1)),
                "nocase": False,
                "offset": None,
                "depth": None,
                "distance": None,
                "within": None,
            }
            contents.append(current)
            payload_checks.append({"type": "content", "value": current})
            inline_modifiers = content_match.group(3)
            if inline_modifiers:
                for modifier in inline_modifiers.split(","):
                    if modifier.strip():
                        _apply_content_modifier(modifier, current, ignored_options)
        elif _modifier_parts(option)[0] in CONTENT_MODIFIERS:
            _apply_content_modifier(option, current, ignored_options)
        elif keyword == "pcre":
            current = None
            pcre = _parse_pcre(value, len(pcres) + 1)
            pcres.append(pcre)
            payload_checks.append({"type": "pcre", "value": pcre})
        elif keyword == "msg":
            message = value.strip('"')
        elif keyword == "sid":
            sid = value
        elif keyword not in {"rev", "classtype", "metadata", "reference"}:
            ignored_options.append(option)
    if not payload_checks:
        raise AnalysisError("The rule must contain at least one content or pcre option.")
    return {
        "text": rule,
        "action": action,
        "protocol": protocol.casefold(),
        "source_net": source_net,
        "source_port": source_port,
        "direction": direction,
        "destination_net": destination_net,
        "destination_port": destination_port,
        "message": message,
        "sid": sid,
        "contents": contents,
        "pcres": pcres,
        "payload_checks": payload_checks,
        "ignored_options": ignored_options,
        "service_header": service_header,
    }


def _display_bytes(value):
    printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value)
    return printable, value.hex(" ")


def _match_content(payload, content, cursor):
    start = content["offset"] if content["offset"] is not None else 0
    if content["distance"] is not None:
        start = cursor + content["distance"]
    start = max(0, start)
    end = len(payload)
    if content["depth"] is not None:
        end = min(end, (content["offset"] or 0) + content["depth"])
    if content["within"] is not None:
        end = min(end, start + content["within"])
    haystack = payload[start:end]
    needle = content["value"]
    position = haystack.lower().find(needle.lower()) if content["nocase"] else haystack.find(needle)
    found = position >= 0
    matched = not found if content["negated"] else found
    absolute_offset = start + position if found else None
    printable, hexadecimal = _display_bytes(needle)
    detail = {
        "index": content["index"],
        "source": content["source"],
        "display": printable,
        "hex": hexadecimal,
        "negated": content["negated"],
        "nocase": content["nocase"],
        "matched": matched,
        "found": found,
        "offset": absolute_offset,
        "search_start": start,
        "search_end": end,
    }
    next_cursor = absolute_offset + len(needle) if found else cursor
    return matched, detail, next_cursor


def _match_pcre(payload, pcre, cursor):
    start = cursor if pcre["relative"] else 0
    found_match = None
    timed_out = False
    reason = pcre["unsupported_reason"]
    if pcre["supported"]:
        try:
            found_match = pcre["_compiled"].search(
                payload, pos=start, timeout=PCRE_TIMEOUT_SECONDS
            )
        except TimeoutError:
            timed_out = True
            reason = f"PCRE evaluation exceeded {PCRE_TIMEOUT_SECONDS * 1000:g} ms."
        except (pcre_regex.error, ValueError) as exc:
            reason = f"PCRE evaluation failed: {exc}"
    found = found_match is not None
    matched = (not found if pcre["negated"] else found) and not reason
    detail = {
        "index": pcre["index"],
        "source": pcre["source"],
        "expression": pcre["expression"],
        "flags": pcre["flags"],
        "negated": pcre["negated"],
        "relative": pcre["relative"],
        "supported": pcre["supported"] and not timed_out and not reason,
        "unsupported_reason": reason,
        "timed_out": timed_out,
        "matched": matched,
        "found": found,
        "offset": found_match.start() if found else None,
        "match_end": found_match.end() if found else None,
        "search_start": start,
        "search_end": len(payload),
    }
    next_cursor = found_match.end() if found and not pcre["negated"] else cursor
    return matched, detail, next_cursor


def match_contents(payload, contents):
    """Match ordered Snort content values against one transport payload."""
    cursor = 0
    details = []
    complete = True
    for content in contents:
        matched, detail, cursor = _match_content(payload, content, cursor)
        details.append(detail)
        complete = complete and matched
    return complete, details


def match_payload_checks(payload, checks):
    """Evaluate content and PCRE options in their original Snort rule order."""
    cursor = 0
    content_details = []
    pcre_details = []
    complete = True
    for check in checks:
        if check["type"] == "content":
            matched, detail, cursor = _match_content(payload, check["value"], cursor)
            content_details.append(detail)
        else:
            matched, detail, cursor = _match_pcre(payload, check["value"], cursor)
            pcre_details.append(detail)
        complete = complete and matched
    return complete, content_details, pcre_details


def _field(layer, name, default=""):
    try:
        value = getattr(layer, name)
    except (AttributeError, KeyError):
        return default
    return str(value or default)


def _payload_bytes(packet):
    for layer_name in ("tcp", "udp", "data"):
        layer = getattr(packet, layer_name, None)
        value = _field(layer, "payload" if layer_name != "data" else "data") if layer else ""
        if not value:
            continue
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(cleaned) % 2:
            continue
        try:
            return bytes.fromhex(cleaned), f"{layer_name.upper()} payload"
        except ValueError:
            continue
    return b"", "No decoded transport payload"


def _network_matches(expected, actual):
    if expected.casefold() == "any" or expected.startswith("$") or expected.startswith("["):
        return True
    if not actual or actual == "Unavailable":
        return False
    try:
        return ipaddress.ip_address(actual) in ipaddress.ip_network(expected, strict=False)
    except ValueError:
        return True


def _port_matches(expected, actual):
    if expected.casefold() == "any" or expected.startswith("$") or expected.startswith("["):
        return True
    if not actual:
        return False
    if ":" in expected:
        lower, _, upper = expected.partition(":")
        try:
            number = int(actual)
            return (not lower or number >= int(lower)) and (not upper or number <= int(upper))
        except ValueError:
            return True
    try:
        return int(expected) == int(actual)
    except ValueError:
        return True


def _header_matches(rule, protocol, source_ip, source_port, destination_ip, destination_port):
    protocol_match = rule.get("service_header") or rule["protocol"] in {"ip", protocol.casefold()}

    def direction_matches(src_ip, src_port, dst_ip, dst_port):
        return (
            _network_matches(rule["source_net"], src_ip)
            and _port_matches(rule["source_port"], src_port)
            and _network_matches(rule["destination_net"], dst_ip)
            and _port_matches(rule["destination_port"], dst_port)
        )

    forward = direction_matches(source_ip, source_port, destination_ip, destination_port)
    reverse = direction_matches(destination_ip, destination_port, source_ip, source_port)
    if rule["direction"] == "<-":
        return protocol_match and reverse
    if rule["direction"] == "<>":
        return protocol_match and (forward or reverse)
    return protocol_match and forward


def _timestamp(value):
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError):
        return "Unavailable"


def analyze(pcap_path, rule_text, max_packets=MAX_PACKETS):
    """Inspect a PCAP and return presentation-safe rule content matches."""
    path = Path(pcap_path).resolve()
    if not path.is_file() or path.suffix.casefold() != ".pcap":
        raise AnalysisError("The selected PCAP is unavailable.")
    rule = parse_rule(rule_text)
    packet_limit = min(max(1, int(max_packets)), MAX_PACKETS)
    protocol_counts = Counter()
    endpoints = Counter()
    packet_rows = []
    match_rows = []
    matched_packet_count = 0
    analyzed = 0
    first_timestamp = None
    last_timestamp = None
    total_wire_bytes = 0
    capture = None
    try:
        capture = pyshark.FileCapture(str(path), keep_packets=False, use_json=True)
        for packet in capture:
            if analyzed >= packet_limit:
                break
            analyzed += 1
            protocol = str(getattr(packet, "transport_layer", "") or getattr(packet, "highest_layer", "Unknown")).upper()
            ip_layer = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
            source_ip = _field(ip_layer, "src", "Unavailable") if ip_layer else "Unavailable"
            destination_ip = _field(ip_layer, "dst", "Unavailable") if ip_layer else "Unavailable"
            transport_layer = getattr(packet, protocol.casefold(), None)
            source_port = _field(transport_layer, "srcport", "") if transport_layer else ""
            destination_port = _field(transport_layer, "dstport", "") if transport_layer else ""
            payload, buffer_name = _payload_bytes(packet)
            payload_match, content_details, pcre_details = match_payload_checks(
                payload, rule["payload_checks"]
            )
            content_match = all(item["matched"] for item in content_details)
            pcre_match = all(item["matched"] for item in pcre_details)
            header_match = _header_matches(rule, protocol, source_ip, source_port, destination_ip, destination_port)
            full_match = header_match and payload_match
            sniff_timestamp = getattr(packet, "sniff_timestamp", None)
            if first_timestamp is None:
                first_timestamp = sniff_timestamp
            last_timestamp = sniff_timestamp
            try:
                wire_length = int(getattr(packet, "length", 0) or 0)
            except (TypeError, ValueError):
                wire_length = 0
            total_wire_bytes += wire_length
            protocol_counts[protocol] += 1
            endpoints[(source_ip, destination_ip)] += 1
            row = {
                "number": analyzed,
                "timestamp": _timestamp(sniff_timestamp),
                "protocol": protocol,
                "source": f"{source_ip}:{source_port}" if source_port else source_ip,
                "destination": f"{destination_ip}:{destination_port}" if destination_port else destination_ip,
                "wire_length": wire_length,
                "payload_length": len(payload),
                "buffer": buffer_name,
                "header_match": header_match,
                "content_match": content_match,
                "pcre_match": pcre_match,
                "payload_match": payload_match,
                "full_match": full_match,
                "contents": content_details,
                "pcres": pcre_details,
            }
            if len(packet_rows) < MAX_PACKET_ROWS:
                packet_rows.append(row)
            if full_match and len(match_rows) < MAX_MATCH_ROWS:
                match_rows.append(row)
            if full_match:
                matched_packet_count += 1
    except AnalysisError:
        raise
    except Exception as exc:
        raise AnalysisError("TShark could not decode the selected PCAP.") from exc
    finally:
        if capture is not None:
            try:
                capture.close()
            except OSError:
                pass
    return {
        "capture": {
            "filename": path.name,
            "file_size": path.stat().st_size,
            "packets_analyzed": analyzed,
            "packet_limit": packet_limit,
            "limit_reached": analyzed >= packet_limit,
            "wire_bytes": total_wire_bytes,
            "first_timestamp": _timestamp(first_timestamp),
            "last_timestamp": _timestamp(last_timestamp),
            "protocols": sorted(protocol_counts.items(), key=lambda item: (-item[1], item[0])),
            "top_conversations": [
                {"source": pair[0], "destination": pair[1], "packets": count}
                for pair, count in endpoints.most_common(15)
            ],
        },
        "rule": rule,
        "matched_packet_count": matched_packet_count,
        "matches": match_rows,
        "packets": packet_rows,
        "packet_rows_truncated": analyzed > len(packet_rows),
        "match_rows_truncated": matched_packet_count > len(match_rows),
    }


def summary_lines(result):
    """Return a concise, presentation-safe summary for replay and Jira output."""
    capture = result.get("capture") or {}
    rule = result.get("rule") or {}
    match_count = int(result.get("matched_packet_count") or 0)
    packet_count = int(capture.get("packets_analyzed") or 0)
    protocols = capture.get("protocols") or []
    protocol_text = ", ".join(f"{name}: {count}" for name, count in protocols) or "None decoded"
    content_count = len(rule.get("contents") or [])
    pcre_count = len(rule.get("pcres") or [])
    verdict = "MATCH" if match_count else "NO MATCH"
    lines = [
        f"PCAP: {capture.get('filename', 'Unknown')}",
        f"Analyzer verdict: {verdict}",
        f"Packets analyzed: {packet_count}",
        f"Packets matching all supported rule conditions: {match_count}",
        f"Content options evaluated: {content_count}",
        f"PCRE options evaluated: {pcre_count}",
        f"Protocols: {protocol_text}",
    ]
    matches = result.get("matches") or []
    if matches:
        numbers = ", ".join(str(item.get("number")) for item in matches[:20])
        lines.append(f"Matching packet numbers: {numbers}")
    if capture.get("limit_reached"):
        lines.append(f"Analysis stopped at the {capture.get('packet_limit')} packet safety limit.")
    if rule.get("ignored_options"):
        lines.append(
            "Inspector did not model: " + "; ".join(str(item) for item in rule["ignored_options"])
        )
    unsupported_pcres = [
        pcre for pcre in rule.get("pcres") or [] if not pcre.get("supported")
    ]
    if unsupported_pcres:
        lines.append(f"Unsupported PCRE options: {len(unsupported_pcres)}")
    return lines


def summary_sections(result, *, include_packet_sample=True):
    """Build bounded Test PCAP/Jira sections from detailed analyzer results."""
    rule = result.get("rule") or {}
    has_contents = bool(rule.get("contents"))
    has_pcres = bool(rule.get("pcres"))

    def verdict(packet, key, applicable):
        if not applicable:
            return "N/A"
        return "Match" if packet.get(key) else "Miss"

    content_items = []
    for content in rule.get("contents") or []:
        modifiers = []
        if content.get("nocase"):
            modifiers.append("nocase")
        for name in ("offset", "depth", "distance", "within"):
            if content.get(name) is not None:
                modifiers.append(f"{name}={content[name]}")
        content_items.append(
            f"Content #{content.get('index', '?')}: "
            f"{'!' if content.get('negated') else ''}\"{content.get('source', '')}\" | "
            f"Hex: {content.get('value', b'').hex(' ') or '—'} | "
            f"Modifiers: {', '.join(modifiers) or 'none'}"
        )
    for pcre in rule.get("pcres") or []:
        content_items.append(
            f"PCRE #{pcre.get('index', '?')}: "
            f"{'!' if pcre.get('negated') else ''}/{pcre.get('source', '')}/"
            f"{pcre.get('flags', '')} | "
            f"Mode: {'relative' if pcre.get('relative') else 'payload start'} | "
            f"Status: {'supported' if pcre.get('supported') else pcre.get('unsupported_reason', 'unsupported')}"
        )
    if not content_items:
        content_items.append("No content or PCRE values were available.")

    matched_items = []
    matches = result.get("matches") or []
    for packet in matches[:MAX_SUMMARY_ROWS]:
        matched_items.append(
            f"Packet {packet.get('number', '?')}: {packet.get('protocol', 'Unknown')} | "
            f"{packet.get('source', 'Unavailable')} → {packet.get('destination', 'Unavailable')} | "
            f"Header: {'Match' if packet.get('header_match') else 'Miss'} | "
            f"Content: {verdict(packet, 'content_match', has_contents)} | "
            f"PCRE: {verdict(packet, 'pcre_match', has_pcres)} | "
            f"Payload: {packet.get('payload_length', 0)} B"
        )
    if len(matches) > MAX_SUMMARY_ROWS:
        matched_items.append(
            f"Showing {MAX_SUMMARY_ROWS} of {len(matches)} retained matched packets."
        )
    if not matched_items:
        matched_items.append("No packets matched every supported rule condition.")

    sample_items = []
    packets = result.get("packets") or []
    for packet in packets[:MAX_SUMMARY_ROWS]:
        sample_items.append(
            f"Packet {packet.get('number', '?')}: {packet.get('timestamp', 'Unavailable')} | "
            f"{packet.get('protocol', 'Unknown')} | "
            f"{packet.get('source', 'Unavailable')} → {packet.get('destination', 'Unavailable')} | "
            f"Payload: {packet.get('payload_length', 0)} B | "
            f"Header: {'Match' if packet.get('header_match') else 'Miss'} | "
            f"Content: {verdict(packet, 'content_match', has_contents)} | "
            f"PCRE: {verdict(packet, 'pcre_match', has_pcres)}"
        )
    if len(packets) > MAX_SUMMARY_ROWS or result.get("packet_rows_truncated"):
        sample_items.append(f"Packet sample limited to the first {MAX_SUMMARY_ROWS} displayed rows.")
    if not sample_items:
        sample_items.append("No decoded packet rows were available.")

    sections = [
        {"label": "CONTENT OPTIONS", "title": "Values evaluated", "items": content_items},
        {
            "label": "MATCHED PACKETS",
            "title": "Header, content, and PCRE matches",
            "items": matched_items,
        },
    ]
    if include_packet_sample:
        sections.append(
            {
                "label": "PACKET SAMPLE",
                "title": "Decoded capture inventory",
                "items": sample_items,
            }
        )
    return sections


def flatten_summary(overview, sections):
    """Encode structured analyzer sections for private replay-result storage."""
    lines = list(overview or [])
    for section in sections or []:
        lines.extend(
            [
                SUMMARY_SECTION_PREFIX + str(section.get("label", "")),
                SUMMARY_TITLE_PREFIX + str(section.get("title", "")),
                *(str(item) for item in section.get("items") or []),
            ]
        )
    return lines
