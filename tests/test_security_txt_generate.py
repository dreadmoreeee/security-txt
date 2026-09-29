import json
from datetime import datetime, timezone

from security_txt.cli import main
from security_txt.core import analyze
from security_txt.generate import build

NOW = datetime(2026, 6, 1, 12, 30, 45, 999, tzinfo=timezone.utc)


def test_build_roundtrip():
    text, warnings, a = build({
        "contact": ["mailto:s@example.com", "tel:+15550100"],
        "preferred_languages": "en, fr",
        "canonical": "https://example.com/.well-known/security.txt",
        "policy": "https://example.com/p", "hiring": "https://example.com/j",
        "encryption": "https://example.com/key.asc",
        "acknowledgments": "https://example.com/thanks",
    }, now=NOW)
    assert not warnings and a.valid
    assert "Expires: 2027-06-01T12:30:45Z\n" in text
    again = analyze(text, NOW)
    assert again.valid and not again.warnings
    assert [f.name for f in again.parsed.fields][:3] == ["Contact", "Contact", "Expires"]


def test_expires_clamped():
    text, warnings, a = build({"contact": "tel:+1", "expires_days": 900}, now=NOW)
    assert warnings and "clamped" in warnings[0]
    assert "Expires: 2027-06-01T12:30:45Z" in text and not a.warnings


def test_expires_days_custom():
    text, _, _ = build({"contact": "tel:+1", "expires_days": 30}, now=NOW)
    assert "Expires: 2026-07-01T12:30:45Z" in text


def test_invalid_input_reported():
    _, _, a = build({"contact": "not-a-uri"}, now=NOW)
    assert not a.valid
    _, _, a = build({}, now=NOW)
    assert "contact-missing" in {i.code for i in a.issues}


def test_cli_generate_stdout_and_file(tmp_path, capsys):
    assert main(["generate", "--contact", "mailto:a@b.co", "--preferred-languages", "en, fr"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Contact: mailto:a@b.co\nExpires: ")
    target = tmp_path / "security.txt"
    assert main(["generate", "--contact", "mailto:a@b.co", "--expires-days", "999",
                 "-o", str(target)]) == 0
    assert "clamped" in capsys.readouterr().err
    assert analyze(target.read_text(encoding="utf-8")).valid


def test_cli_generate_invalid_writes_nothing(tmp_path, capsys):
    target = tmp_path / "x.txt"
    assert main(["generate", "--contact", "bogus", "-o", str(target)]) == 1
    assert not target.exists()
    assert main(["generate", "-o", str(target)]) == 1


def test_cli_from_json(tmp_path, capsys):
    cfg = tmp_path / "o.json"
    cfg.write_text(json.dumps({"contact": ["mailto:a@b.co"], "expires_days": 10,
                               "policy": "https://b.co/p"}), encoding="utf-8")
    assert main(["generate", "--from-json", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "Policy: https://b.co/p" in out
    assert main(["generate", "--from-json", str(tmp_path / "missing.json")]) == 2
