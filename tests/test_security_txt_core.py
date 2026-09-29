from datetime import datetime, timedelta, timezone

from security_txt.core import analyze, parse, parse_expires

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
GOOD = "Contact: mailto:a@example.com\nExpires: 2026-12-31T00:00:00Z\n"


def codes(a, level=None):
    return {i.code for i in a.issues if level is None or i.level == level}


def test_parse_basic_and_comments_crlf():
    p = parse("# hi\r\nContact: mailto:a@b.co\r\n\r\nExpires: 2027-01-01T00:00:00Z\r\n")
    assert [f.name for f in p.fields] == ["Contact", "Expires"]
    assert p.fields[0].line == 2
    assert not p.issues and not p.signed


def test_valid_file():
    a = analyze(GOOD, NOW)
    assert a.valid and not a.warnings
    assert a.days_left == 212.5


def test_syntax_error():
    assert "syntax" in codes(analyze(GOOD + "garbage line\n", NOW), "error")


def test_empty_value():
    assert "empty-value" in codes(analyze(GOOD + "Policy:\n", NOW))


def test_missing_required():
    a = analyze("Policy: https://x.org/p\n", NOW)
    assert {"contact-missing", "expires-missing"} <= codes(a, "error")


def test_contact_must_be_uri():
    a = analyze("Contact: security@example.com\nExpires: 2026-12-31T00:00:00Z\n", NOW)
    assert "contact-uri" in codes(a, "error")
    for ok in ("tel:+1-555-0100", "https://example.com/report"):
        assert analyze(f"Contact: {ok}\nExpires: 2026-12-31T00:00:00Z\n", NOW).valid
    bad = analyze("Contact: http://example.com\nExpires: 2026-12-31T00:00:00Z\n", NOW)
    assert "contact-uri" in codes(bad)


def test_duplicate_expires_and_languages():
    a = analyze(GOOD + "Expires: 2026-12-30T00:00:00Z\nPreferred-Languages: en\n"
                "Preferred-Languages: fr\n", NOW)
    assert "duplicate" in codes(a, "error")
    assert sum(1 for i in a.issues if i.code == "duplicate") == 2


def test_multiple_contacts_ok():
    assert analyze(GOOD + "Contact: tel:+15550100\n", NOW).valid


def test_expires_formats():
    assert analyze("Contact: tel:+1\nExpires: tomorrow\n", NOW).errors[0].code == "expires-format"
    assert "expires-format" in codes(analyze("Contact: tel:+1\nExpires: 2026-12-31T00:00:00\n", NOW))
    assert parse_expires("2026-12-31T00:00:00+02:00") is not None
    assert parse_expires("2026-12-31T00:00:00.5z") is not None
    assert parse_expires("2026-13-31T00:00:00Z") is None


def test_expiry_math():
    def exp(dt):
        return f"Contact: tel:+1\nExpires: {dt.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
    assert "expired" in codes(analyze(exp(NOW - timedelta(seconds=1)), NOW), "error")
    assert analyze(exp(NOW + timedelta(days=365)), NOW).valid
    far = analyze(exp(NOW + timedelta(days=366)), NOW)
    assert far.valid and "expires-far" in codes(far, "warning")
    a = analyze(exp(NOW + timedelta(days=10)), NOW)
    assert round(a.days_left) == 10


def test_optional_field_validation():
    a = analyze(GOOD + "Encryption: notauri\nPolicy: http://x.org/p\nHiring: https://x.org/j\n"
                "Acknowledgments: /thanks\n", NOW)
    assert {"encryption-uri", "policy-uri", "acknowledgments-uri"} <= codes(a, "error")
    assert "hiring-uri" not in codes(a)
    assert analyze(GOOD + "Encryption: openpgp4fpr:ABCDEF0123\n", NOW).valid


def test_preferred_languages():
    assert analyze(GOOD + "Preferred-Languages: en, fr-CA, zh-Hant\n", NOW).valid
    assert "language-tag" in codes(analyze(GOOD + "Preferred-Languages: en; fr\n", NOW))
    assert "language-tag" in codes(analyze(GOOD + "Preferred-Languages: en,,fr\n", NOW))


def test_canonical_check():
    url = "https://example.com/.well-known/security.txt"
    ok = analyze(GOOD + f"Canonical: {url}\n", NOW, source_url=url)
    assert not ok.warnings
    bad = analyze(GOOD + "Canonical: https://other.org/.well-known/security.txt\n", NOW,
                  source_url=url)
    assert "canonical-mismatch" in codes(bad, "warning") and bad.valid


def test_unknown_field_warning_once():
    a = analyze(GOOD + "X-Foo: 1\nx-foo: 2\n", NOW)
    assert a.valid and sum(1 for i in a.warnings if i.code == "unknown-field") == 1


def test_field_names_case_insensitive():
    assert analyze("CONTACT: tel:+1\nexpires: 2026-12-31T00:00:00Z\n", NOW).valid
