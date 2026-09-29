"""Fetching and checking a domain's security.txt locations."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .core import Analysis, Issue, analyze, check_content_type

USER_AGENT = "security-txt/1.0 (+https://github.com/dreadmoreeee/security-txt)"
MAX_BYTES = 256 * 1024
WELL_KNOWN = "/.well-known/security.txt"
LEGACY = "/security.txt"


@dataclass
class Fetched:
    url: str
    final_url: str | None = None
    status: int | None = None
    content_type: str | None = None
    body: bytes = b""
    error: str | None = None  # network-level error

    @property
    def redirected(self) -> bool:
        return bool(self.final_url) and self.final_url != self.url

    @property
    def not_found(self) -> bool:
        return self.status in (404, 410)


def fetch(url: str, timeout: float = 10.0) -> Fetched:
    """GET a URL. Never raises; network problems go into `.error`."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "text/plain, */*;q=0.1"})
    res = Fetched(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res.status = r.status
            res.final_url = r.geturl()
            res.content_type = r.headers.get("Content-Type")
            res.body = r.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        res.status = e.code
        res.final_url = e.geturl()
        res.content_type = e.headers.get("Content-Type") if e.headers else None
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        res.error = f"{type(reason).__name__}: {reason}"
    return res


@dataclass
class FileReport:
    path: str
    fetched: Fetched
    analysis: Analysis | None = None
    issues: list | None = None  # transport-level + content issues

    @property
    def found(self) -> bool:
        return self.analysis is not None

    @property
    def valid(self) -> bool:
        return self.found and not any(i.level == "error" for i in self.issues)

    def to_dict(self) -> dict:
        f = self.fetched
        d = {
            "path": self.path,
            "url": f.url,
            "final_url": f.final_url,
            "redirected": f.redirected,
            "status": f.status,
            "found": self.found,
            "not_found": f.not_found,
            "network_error": f.error,
            "content_type": f.content_type,
            "valid": self.valid,
        }
        if self.analysis:
            p = self.analysis.parsed
            d["signed"] = p.signed
            d["fields"] = [{"name": x.name, "value": x.value, "line": x.line} for x in p.fields]
            d["expires"] = self.analysis.expires.isoformat() if self.analysis.expires else None
            d["days_left"] = (round(self.analysis.days_left, 2)
                              if self.analysis.days_left is not None else None)
            d["errors"] = [i.to_dict() for i in self.issues if i.level == "error"]
            d["warnings"] = [i.to_dict() for i in self.issues if i.level == "warning"]
        return d


def build_report(path: str, fetched: Fetched, now: datetime, require_https: bool) -> FileReport:
    rep = FileReport(path, fetched)
    if fetched.error or fetched.status != 200:
        return rep
    issues: list = []
    if len(fetched.body) > MAX_BYTES:
        issues.append(Issue("error", "too-large", f"file is larger than {MAX_BYTES} bytes"))
        rep.analysis = analyze("", now)
        rep.issues = issues
        return rep
    if require_https and urlsplit(fetched.final_url or "").scheme != "https":
        issues.append(Issue("error", "not-https", "file must be served over HTTPS"))
    check_content_type(fetched.content_type, issues)
    try:
        text = fetched.body.decode("utf-8")
    except UnicodeDecodeError:
        issues.append(Issue("error", "encoding", "body is not valid UTF-8"))
        text = fetched.body.decode("utf-8", errors="replace")
    a = analyze(text, now, source_url=fetched.final_url or fetched.url)
    rep.analysis = a
    rep.issues = issues + a.issues
    return rep


@dataclass
class DomainResult:
    domain: str
    well_known: FileReport
    legacy: FileReport
    watch_days: int | None = None

    @property
    def expiry_soon(self) -> bool:
        a = self.well_known.analysis
        return bool(self.watch_days is not None and a and a.days_left is not None
                    and a.days_left <= self.watch_days)

    @property
    def valid(self) -> bool:
        return self.well_known.valid

    @property
    def exit_code(self) -> int:
        if self.well_known.fetched.error:
            return 2
        if not self.valid or self.expiry_soon:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "valid": self.valid and not self.expiry_soon,
            "expiry_watch_days": self.watch_days,
            "expiry_soon": self.expiry_soon,
            "well_known": self.well_known.to_dict(),
            "legacy": self.legacy.to_dict(),
            "legacy_redirects": self.legacy.fetched.redirected,
            "exit_code": self.exit_code,
        }


def check_domain(domain: str, scheme: str = "https", now: datetime | None = None,
                 timeout: float = 10.0, delay: float = 1.0,
                 watch_days: int | None = None) -> DomainResult:
    """Fetch both locations (2 GETs, `delay` seconds apart) and validate them.

    HTTPS is enforced when scheme == "https"; tests pass scheme="http" for local servers.
    """
    now = now or datetime.now(timezone.utc)
    require_https = scheme == "https"
    wk = fetch(f"{scheme}://{domain}{WELL_KNOWN}", timeout)
    if delay:
        time.sleep(delay)
    lg = fetch(f"{scheme}://{domain}{LEGACY}", timeout)
    return DomainResult(domain,
                        build_report(WELL_KNOWN, wk, now, require_https),
                        build_report(LEGACY, lg, now, require_https),
                        watch_days)
