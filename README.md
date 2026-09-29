# security-txt

Check and generate [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) `security.txt` files. Pure Python standard library, no dependencies. Python 3.10+.

## Install

```
pip install .
```

Or run without installing: `python -m security_txt ...`

## Check a domain

```
security-txt check example.com
security-txt check example.com --json
security-txt check example.com --watch-expiry 30
```

It fetches `https://<domain>/.well-known/security.txt` and the legacy `/security.txt` (GET only, 2 requests, 1 s apart), reports both, and notes if the legacy path redirects.

Checked rules:

- `Contact` (at least one, URI: `mailto:`, `https:`, `tel:`) and `Expires` (exactly one, RFC 3339, in the future; warning if more than 1 year away).
- `Encryption` (URI), `Acknowledgments`, `Canonical`, `Policy`, `Hiring` (https URIs), `Preferred-Languages` (at most one, language tags). `Canonical` should include the URL the file was fetched from. Unknown fields are warnings.
- HTTPS only, `Content-Type: text/plain` (charset should be utf-8), line syntax (`field: value`, `#` comments, CRLF or LF), and duplicates of single-use fields.
- PGP cleartext-signed files: the armor structure (`BEGIN PGP SIGNED MESSAGE`, `Hash:` header, signature block) is validated and the signed content is parsed. No cryptographic verification is done.

Exit codes: `0` valid, `1` invalid or missing (or `Expires` within `--watch-expiry N` days), `2` network or usage error.

## Generate a file

```
security-txt generate --contact mailto:security@example.com \
    --preferred-languages "en, fr" \
    --canonical https://example.com/.well-known/security.txt -o security.txt
security-txt generate --from-json examples/options.json
```

Flags: `--contact` (repeatable), `--expires-days` (default 365, clamped to 365 with a warning), `--encryption`, `--acknowledgments`, `--preferred-languages`, `--canonical`, `--policy`, `--hiring`, `--from-json`, `-o`. `Expires` is computed in UTC. The output is validated with the same checker before it is written; an invalid result writes nothing and exits 1.

## Tests

```
python -m pytest -q -p no:cacheprovider --import-mode=importlib security-txt
```

Tests use local servers on random ports; no internet is needed. The scheme is injectable (`--scheme http`, `check_domain(scheme="http")`) for local testing; production enforces HTTPS.

## Measured result

Run on 2026-09-29 against the author's own sites (4 GET requests per site over two runs, at least 1 s apart):

```
security.txt check for demarkstudio.ca

[well-known] https://demarkstudio.ca/.well-known/security.txt
  HTTP 404: not found

[legacy] https://demarkstudio.ca/security.txt
  redirected to: https://demarkstudio.ca/security.txt/
  HTTP 404: not found (optional legacy location)
  note: legacy /security.txt redirects

Overall: INVALID or MISSING
exit code: 1
```

`demo.demarkstudio.ca` gave the same result (both paths 404, legacy redirected to `/security.txt/`). `marvin.demarkstudio.ca` returned 404 on both paths with no redirect. All three exit with code 1: none publishes a `security.txt` yet.

Generated for demarkstudio.ca (`mailto:security@demarkstudio.ca` is a **suggested** placeholder; the owner must confirm it):

```
Contact: mailto:security@demarkstudio.ca
Expires: 2027-09-29T09:40:28Z
Preferred-Languages: en, fr
Canonical: https://demarkstudio.ca/.well-known/security.txt
```

After this run I added the file to my portfolio's build (Expires renewed on every build) and checked it again:

```
$ python -m security_txt check marvin.demarkstudio.ca
[well-known] https://marvin.demarkstudio.ca/.well-known/security.txt
  HTTP 200  Content-Type: text/plain; charset=utf-8
  Contact: mailto:hola@demarkstudio.ca
  Expires: 2027-09-29T00:00:00Z
  Preferred-Languages: en, es
  Canonical: https://marvin.demarkstudio.ca/.well-known/security.txt
  expires in 365 days
  result: VALID
Overall: VALID
exit code: 0
```

Test suite: `42 passed in 11.25s`

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
