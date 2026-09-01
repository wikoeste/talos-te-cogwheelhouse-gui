"""Short-lived private storage for replay results awaiting a Jira post."""

import json
import os
import re
import secrets
import time
from pathlib import Path


STORE_DIR = Path(
    os.getenv(
        "REPLAY_POST_STATE_DIR",
        str(Path.home() / ".local" / "share" / "talos-te-cogwheelhouse" / "replay-posts"),
    )
).expanduser().resolve()
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
TTL_SECONDS = max(60, min(int(os.getenv("REPLAY_POST_TTL_SECONDS", "1800")), 86400))
MAX_STORED_CHARS = max(
    10000,
    min(int(os.getenv("REPLAY_POST_MAX_CHARS", "200000")), 1000000),
)


class ReplayPostError(RuntimeError):
    """Raised when staged replay results cannot be safely stored or loaded."""


def _directory():
    STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    STORE_DIR.chmod(0o700)
    return STORE_DIR


def _path(token):
    if not TOKEN_PATTERN.fullmatch(str(token or "")):
        raise ReplayPostError("The replay result token is invalid.")
    return _directory() / f"{token}.json"


def _bounded_lines(values, remaining):
    lines = []
    for value in values or []:
        line = str(value).replace("\x00", "").replace("\r", "")
        if len(line) > remaining:
            if remaining > 80:
                lines.append(line[: remaining - 55] + "\n[Output truncated by COG Wheelhouse]")
            return lines, 0
        lines.append(line)
        remaining -= len(line)
    return lines, remaining


def _cleanup(now=None):
    cutoff = (time.time() if now is None else now) - TTL_SECONDS
    try:
        entries = list(_directory().glob("*.json"))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink(missing_ok=True)
        except OSError:
            continue


def store_result(*, sid, snort_version, policy, capture_summary, runtime_alerts, content_analysis=None):
    """Store bounded replay data server-side and return an opaque browser token."""
    _cleanup()
    remaining = MAX_STORED_CHARS
    summary, remaining = _bounded_lines(capture_summary, remaining)
    analysis, remaining = _bounded_lines(content_analysis, remaining)
    runtime, _ = _bounded_lines(runtime_alerts, remaining)
    payload = {
        "expires_at": int(time.time()) + TTL_SECONDS,
        "sid": str(sid),
        "snort_version": str(snort_version),
        "policy": str(policy),
        "capture_summary": summary,
        "content_analysis": analysis,
        "runtime_alerts": runtime,
    }
    token = secrets.token_urlsafe(32)
    try:
        target = _path(token)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False)
    except OSError as exc:
        raise ReplayPostError("Unable to save replay results for Jira posting.") from exc
    return token


def load_result(token):
    """Load unexpired results without trusting browser-supplied replay output."""
    try:
        target = _path(token)
        if target.stat().st_size > MAX_STORED_CHARS * 2:
            raise ReplayPostError("The stored replay result exceeded the safety limit.")
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReplayPostError("The replay results expired; run the PCAP test again.") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise ReplayPostError("The stored replay results could not be read.") from exc
    if not isinstance(payload, dict) or payload.get("expires_at", 0) < time.time():
        target.unlink(missing_ok=True)
        raise ReplayPostError("The replay results expired; run the PCAP test again.")
    return payload


def discard_result(token):
    """Remove staged results after posting or declining the Jira update."""
    try:
        _path(token).unlink(missing_ok=True)
    except (OSError, ReplayPostError):
        pass
