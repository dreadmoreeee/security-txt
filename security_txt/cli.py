"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .generate import build
from .net import DomainResult, FileReport, check_domain


def _clean_domain(value: str) -> str:
    v = value.strip()
    for prefix in ("https://", "http://"):
        if v.lower().startswith(prefix):
            v = v[len(prefix):]
    return v.split("/")[0]


def _render_file(rep: FileReport, label: str, optional: bool = False) -> list:
    f = rep.fetched
    out = [f"[{label}] {f.url}"]
    if f.error:
        out.append(f"  network error: {f.error}")
        return out
    if f.redirected and f.status != 200:
        out.append(f"  redirected to: {f.final_url}")
    if f.not_found:
        out.append(f"  HTTP {f.status}: not found" + (" (optional legacy location)" if optional else ""))
        return out
    if f.status != 200:
        out.append(f"  HTTP {f.status}: unexpected status")
        return out
    out.append(f"  HTTP {f.status}  Content-Type: {f.content_type or '(none)'}")
    if f.redirected:
        out.append(f"  redirected to: {f.final_url}")
    a = rep.analysis
    out.append("  signed (PGP armor): " + ("yes" if a.parsed.signed else "no"))
    for fld in a.parsed.fields:
        out.append(f"  {fld.name}: {fld.value}")
    if a.days_left is not None:
        out.append(f"  expires in {a.days_left:.0f} days")
    for i in rep.issues:
        out.append(f"  {'ERROR' if i.level == 'error' else 'WARN '} {i.message}")
    out.append("  result: " + ("VALID" if rep.valid else "INVALID"))
    return out


def render_text(res: DomainResult) -> str:
    out = [f"security.txt check for {res.domain}", ""]
    out += _render_file(res.well_known, "well-known")
    out.append("")
    out += _render_file(res.legacy, "legacy", optional=True)
    if res.legacy.fetched.redirected:
        out.append("  note: legacy /security.txt redirects")
    out.append("")
    if res.well_known.fetched.error:
        out.append("Overall: ERROR (network)")
    elif res.expiry_soon:
        out.append(f"Overall: EXPIRING (expires within {res.watch_days} days)")
    else:
        out.append("Overall: " + ("VALID" if res.valid else "INVALID or MISSING"))
    return "\n".join(out)


def _cmd_check(args) -> int:
    domain = _clean_domain(args.domain)
    if not domain:
        print("error: empty domain", file=sys.stderr)
        return 2
    res = check_domain(domain, scheme=args.scheme, timeout=args.timeout,
                       delay=args.delay, watch_days=args.watch_expiry)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(render_text(res))
    return res.exit_code


def _cmd_generate(args) -> int:
    opts = {}
    try:
        if args.from_json:
            with open(args.from_json, encoding="utf-8") as fh:
                opts = json.load(fh)
            if not isinstance(opts, dict):
                raise ValueError("JSON root must be an object")
    except (OSError, ValueError) as e:
        print(f"error: cannot read --from-json: {e}", file=sys.stderr)
        return 2
    for key in ("contact", "encryption", "acknowledgments", "canonical", "policy", "hiring"):
        val = getattr(args, key)
        if val:
            opts[key] = val
    if args.preferred_languages:
        opts["preferred_languages"] = args.preferred_languages
    if args.expires_days is not None:
        opts["expires_days"] = args.expires_days
    try:
        text, warnings, analysis = build(opts)
    except (ValueError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    for i in analysis.issues:
        print(f"{i.level}: {i.message}", file=sys.stderr)
    if not analysis.valid:
        print("error: generated file is not valid; nothing written", file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-txt",
                                description="Check and generate RFC 9116 security.txt files.")
    p.add_argument("--version", action="version", version=f"security-txt {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="fetch and validate a domain's security.txt")
    c.add_argument("domain")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.add_argument("--watch-expiry", type=int, metavar="N",
                   help="exit 1 if Expires is within N days")
    c.add_argument("--timeout", type=float, default=10.0)
    c.add_argument("--delay", type=float, default=1.0, help="seconds between the two requests")
    c.add_argument("--scheme", default="https", choices=("https", "http"),
                   help="http is for local testing only")
    c.set_defaults(func=_cmd_check)

    g = sub.add_parser("generate", help="build a valid security.txt")
    g.add_argument("--contact", action="append", help="URI (mailto:, https:, tel:); repeatable")
    g.add_argument("--expires-days", type=int, default=None, help="default 365, max 365")
    g.add_argument("--encryption", action="append")
    g.add_argument("--acknowledgments", action="append")
    g.add_argument("--preferred-languages", help="comma-separated, e.g. 'en, fr'")
    g.add_argument("--canonical", action="append")
    g.add_argument("--policy", action="append")
    g.add_argument("--hiring", action="append")
    g.add_argument("--from-json", metavar="FILE")
    g.add_argument("-o", "--output", metavar="FILE")
    g.set_defaults(func=_cmd_generate)
    return p


def main(argv=None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    return args.func(args)
