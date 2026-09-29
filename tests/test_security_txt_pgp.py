from datetime import datetime, timezone

from security_txt.core import analyze, parse

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
SIG = ("-----BEGIN PGP SIGNATURE-----\n\niQEzBAEBCAAdFiEEabc123+/xyz\nabcdEFGH==\n=AbC1\n"
       "-----END PGP SIGNATURE-----\n")


def signed(body="Contact: mailto:a@b.co\nExpires: 2026-12-31T00:00:00Z\n", hdr="Hash: SHA512\n",
           sig=SIG):
    return f"-----BEGIN PGP SIGNED MESSAGE-----\n{hdr}\n{body}\n{sig}"


def codes(a):
    return {i.code for i in a.issues}


def test_valid_signed():
    a = analyze(signed(), NOW)
    assert a.valid and a.parsed.signed and a.parsed.hash_algorithms == ["SHA512"]
    assert [f.name for f in a.parsed.fields] == ["Contact", "Expires"]


def test_dash_escaped_content():
    p = parse(signed(body="- # comment\n- Contact: tel:+1\n"))
    assert [f.name for f in p.fields] == ["Contact"]


def test_missing_hash_is_warning():
    a = analyze(signed(hdr=""), NOW)
    assert a.valid and "pgp-no-hash" in codes(a)


def test_missing_signature():
    a = analyze("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: tel:+1\n"
                "Expires: 2026-12-31T00:00:00Z\n", NOW)
    assert "pgp-no-signature" in codes(a) and not a.valid


def test_missing_end():
    a = analyze(signed(sig="-----BEGIN PGP SIGNATURE-----\n\nabcd\n"), NOW)
    assert "pgp-no-end" in codes(a)


def test_bad_base64_and_crc():
    bad = SIG.replace("abcdEFGH==", "ab cd!!")
    assert "pgp-bad-base64" in codes(analyze(signed(sig=bad), NOW))
    assert "pgp-bad-crc" in codes(analyze(signed(sig=SIG.replace("=AbC1", "=zz")), NOW))


def test_empty_signature():
    sig = "-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"
    assert "pgp-empty-signature" in codes(analyze(signed(sig=sig), NOW))


def test_armor_not_at_start():
    a = analyze("Contact: tel:+1\n" + signed(), NOW)
    assert "pgp-structure" in codes(a)


def test_trailing_text_warning():
    assert "pgp-trailing" in codes(analyze(signed(sig=SIG + "junk\n"), NOW))
