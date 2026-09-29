"""Generate a valid RFC 9116 security.txt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .core import Analysis, analyze

MAX_DAYS = 365
MULTI = ("contact", "encryption", "acknowledgments", "canonical", "policy", "hiring")


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def format_expires(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(options: dict, now: datetime | None = None):
    """Build file text from options. Returns (text, warnings, analysis).

    Option keys: contact, encryption, acknowledgments, canonical, policy, hiring
    (str or list), preferred_languages (str), expires_days (int, default 365).
    """
    now = now or datetime.now(timezone.utc)
    warnings = []
    days = options.get("expires_days")
    days = MAX_DAYS if days is None else int(days)
    if days > MAX_DAYS:
        warnings.append(f"--expires-days {days} exceeds {MAX_DAYS}; clamped to {MAX_DAYS}")
        days = MAX_DAYS
    if days < 1:
        raise ValueError("expires-days must be at least 1")
    expires = format_expires(now + timedelta(days=days))

    lines = [f"Contact: {c}" for c in _as_list(options.get("contact"))]
    lines.append(f"Expires: {expires}")
    for c in _as_list(options.get("encryption")):
        lines.append(f"Encryption: {c}")
    for c in _as_list(options.get("acknowledgments")):
        lines.append(f"Acknowledgments: {c}")
    langs = options.get("preferred_languages")
    if langs:
        if isinstance(langs, (list, tuple)):
            langs = ", ".join(langs)
        lines.append(f"Preferred-Languages: {langs}")
    for key, label in (("canonical", "Canonical"), ("policy", "Policy"), ("hiring", "Hiring")):
        for c in _as_list(options.get(key)):
            lines.append(f"{label}: {c}")
    text = "\n".join(lines) + "\n"
    analysis: Analysis = analyze(text, now)
    return text, warnings, analysis
