"""Parser and validator for RFC 9116 security.txt files (stdlib only)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

KNOWN_FIELDS = {
    "contact": "Contact",
    "expires": "Expires",
    "encryption": "Encryption",
    "acknowledgments": "Acknowledgments",
    "preferred-languages": "Preferred-Languages",
    "canonical": "Canonical",
    "policy": "Policy",
    "hiring": "Hiring",
}
SINGLE_FIELDS = ("expires", "preferred-languages")
CONTACT_SCHEMES = ("mailto", "https", "tel")
WEB_URI_FIELDS = ("acknowledgments", "canonical", "policy", "hiring")

PGP_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----"
PGP_SIG_BEGIN = "-----BEGIN PGP SIGNATURE-----"
PGP_SIG_END = "-----END PGP SIGNATURE-----"

FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*?)[ \t]*$")
LANG_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")
B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
CRC_RE = re.compile(r"^=[A-Za-z0-9+/]{4}$")


@dataclass
class Issue:
    level: str  # "error" or "warning"
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class Field:
    name: str
    value: str
    line: int


@dataclass
class Parsed:
    fields: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    signed: bool = False
    hash_algorithms: list = field(default_factory=list)

    def get(self, name: str) -> list:
        return [f for f in self.fields if f.name.lower() == name.lower()]


def _err(parsed: Parsed, code: str, msg: str) -> None:
    parsed.issues.append(Issue("error", code, msg))


def _warn(parsed: Parsed, code: str, msg: str) -> None:
    parsed.issues.append(Issue("warning", code, msg))


def _split_lines(text: str) -> list:
    return re.split(r"\r\n|\n", text)


def _validate_armor(lines: list, start: int, parsed: Parsed) -> list:
    """Validate the signed-message armor. Returns the (lineno, text) cleartext lines."""
    i = start
    n = len(lines)
    # armor headers until blank line
    while i < n and lines[i].strip() != "":
        m = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", lines[i])
        if not m:
            _err(parsed, "pgp-header", f"line {i + 1}: malformed PGP armor header")
        elif m.group(1).lower() == "hash":
            parsed.hash_algorithms.extend(
                h.strip() for h in m.group(2).split(",") if h.strip()
            )
        i += 1
    if i >= n:
        _err(parsed, "pgp-structure", "PGP signed message has no blank line after headers")
        return []
    if not parsed.hash_algorithms:
        _warn(parsed, "pgp-no-hash", "PGP signed message has no Hash: header")
    i += 1
    content = []
    while i < n and lines[i] != PGP_SIG_BEGIN:
        text = lines[i]
        if text.startswith("- "):
            text = text[2:]
        content.append((i + 1, text))
        i += 1
    if i >= n:
        _err(parsed, "pgp-no-signature", "missing '-----BEGIN PGP SIGNATURE-----' block")
        return content
    i += 1
    # signature armor headers (Version: ...), then blank line, then base64
    while i < n and lines[i].strip() != "" and ":" in lines[i]:
        i += 1
    if i < n and lines[i].strip() == "":
        i += 1
    body = []
    while i < n and lines[i] != PGP_SIG_END:
        body.append(lines[i].strip())
        i += 1
    if i >= n:
        _err(parsed, "pgp-no-end", "missing '-----END PGP SIGNATURE-----' line")
        return content
    data = [b for b in body if b and not b.startswith("=")]
    crc = [b for b in body if b.startswith("=")]
    if not data:
        _err(parsed, "pgp-empty-signature", "PGP signature block is empty")
    elif not all(B64_RE.match(b) for b in data):
        _err(parsed, "pgp-bad-base64", "PGP signature block is not valid base64 armor")
    if crc and not CRC_RE.match(crc[-1]):
        _err(parsed, "pgp-bad-crc", "PGP armor checksum line is malformed")
    if any(t.strip() for t in lines[i + 1:]):
        _warn(parsed, "pgp-trailing", "text found after the PGP signature block")
    return content


def parse(text: str) -> Parsed:
    """Parse security.txt text, including a cleartext PGP signed variant."""
    parsed = Parsed()
    if text.startswith("\\ufeff"):
        text = text[1:]
        _warn(parsed, "bom", "file starts with a UTF-8 byte order mark")
    lines = _split_lines(text)
    numbered = [(i + 1, t) for i, t in enumerate(lines)]
    first = next((i for i, t in enumerate(lines) if t.strip()), None)
    if first is not None and lines[first].strip() == PGP_BEGIN:
        parsed.signed = True
        numbered = _validate_armor(lines, first + 1, parsed)
    elif PGP_BEGIN in text or PGP_SIG_BEGIN in text:
        _err(parsed, "pgp-structure", "PGP armor found but the file does not start with it")
    for lineno, raw in numbered:
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = FIELD_RE.match(line)
        if not m:
            _err(parsed, "syntax", f"line {lineno}: not 'field-name: value' or a comment")
            continue
        if not m.group(2):
            _err(parsed, "empty-value", f"line {lineno}: field '{m.group(1)}' has no value")
            continue
        parsed.fields.append(Field(m.group(1), m.group(2), lineno))
    return parsed


def parse_expires(value: str):
    """Parse an RFC 3339 timestamp; returns an aware datetime or None."""
    v = value.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:\d{2})$", v):
        return None
    v = v.replace("z", "Z").replace("t", "T")
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else None


def _has_uri(value: str, schemes=None) -> bool:
    parts = urlsplit(value)
    if not parts.scheme:
        return False
    if schemes is not None and parts.scheme.lower() not in schemes:
        return False
    return bool(parts.netloc or parts.path or parts.query)


def _once(parsed: Parsed, name: str) -> list:
    items = parsed.get(name)
    if len(items) > 1:
        _err(parsed, "duplicate", f"'{KNOWN_FIELDS[name]}' must appear only once "
             f"(lines {', '.join(str(f.line) for f in items)})")
    return items


def check_content_type(content_type, issues: list) -> None:
    if not content_type:
        issues.append(Issue("error", "content-type", "no Content-Type header (need text/plain)"))
        return
    parts = [p.strip() for p in content_type.split(";")]
    if parts[0].lower() != "text/plain":
        issues.append(Issue("error", "content-type",
                            f"Content-Type is '{parts[0]}', must be text/plain"))
        return
    charset = None
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip().lower() == "charset":
            charset = v.strip().strip('"').lower()
    if charset is None:
        issues.append(Issue("warning", "charset", "Content-Type has no charset (use charset=utf-8)"))
    elif charset != "utf-8":
        issues.append(Issue("error", "charset", f"charset is '{charset}', must be utf-8"))


@dataclass
class Analysis:
    parsed: Parsed
    issues: list
    expires: object = None  # aware datetime or None
    days_left: object = None  # float or None

    @property
    def errors(self) -> list:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def valid(self) -> bool:
        return not self.errors


def analyze(text: str, now: datetime | None = None, source_url: str | None = None) -> Analysis:
    """Validate file content against RFC 9116. `now` is injectable for tests."""
    now = now or datetime.now(timezone.utc)
    parsed = parse(text)
    issues = parsed.issues  # shared list; validation appends to it

    contacts = parsed.get("contact")
    if not contacts:
        _err(parsed, "contact-missing", "required field 'Contact' is missing")
    for f in contacts:
        if not _has_uri(f.value, CONTACT_SCHEMES):
            _err(parsed, "contact-uri",
                 f"line {f.line}: Contact must be a URI (mailto:, https: or tel:): {f.value}")

    expires_dt = None
    days_left = None
    exp = _once(parsed, "expires")
    if not exp:
        _err(parsed, "expires-missing", "required field 'Expires' is missing")
    else:
        expires_dt = parse_expires(exp[0].value)
        if expires_dt is None:
            _err(parsed, "expires-format",
                 f"line {exp[0].line}: Expires is not an RFC 3339 date-time: {exp[0].value}")
        else:
            days_left = (expires_dt - now).total_seconds() / 86400
            if expires_dt <= now:
                _err(parsed, "expired", f"file expired on {exp[0].value}")
            elif expires_dt > now + timedelta(days=365):
                _warn(parsed, "expires-far",
                      "Expires is more than one year in the future (RFC 9116 recommends less)")

    for f in parsed.get("encryption"):
        if not _has_uri(f.value):
            _err(parsed, "encryption-uri", f"line {f.line}: Encryption must be a URI: {f.value}")
        elif urlsplit(f.value).scheme.lower() == "http":
            _err(parsed, "encryption-http", f"line {f.line}: Encryption web URI must use https")
    for name in WEB_URI_FIELDS:
        for f in parsed.get(name):
            label = KNOWN_FIELDS[name]
            if not _has_uri(f.value, ("https",)):
                _err(parsed, f"{name}-uri", f"line {f.line}: {label} must be an https URI: {f.value}")

    langs = _once(parsed, "preferred-languages")
    if langs:
        tags = [t.strip() for t in langs[0].value.split(",")]
        bad = [t for t in tags if not LANG_RE.match(t)]
        if bad:
            _err(parsed, "language-tag",
                 f"line {langs[0].line}: invalid language tag(s): {', '.join(bad) or '(empty)'}")

    canon = parsed.get("canonical")
    if source_url and canon:
        urls = [c.value.strip().rstrip("/") for c in canon]
        if source_url.rstrip("/") not in urls:
            _warn(parsed, "canonical-mismatch",
                  f"Canonical does not include the URL the file was fetched from ({source_url})")

    seen = set()
    for f in parsed.fields:
        low = f.name.lower()
        if low not in KNOWN_FIELDS and low not in seen:
            seen.add(low)
            _warn(parsed, "unknown-field", f"line {f.line}: unknown field '{f.name}'")

    if not parsed.fields and not parsed.issues:
        _err(parsed, "empty", "file contains no fields")
    return Analysis(parsed, issues, expires_dt, days_left)
