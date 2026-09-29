import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from security_txt.cli import main
from security_txt.net import check_domain, fetch

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
FILE = "Contact: mailto:a@example.com\nExpires: 2026-12-31T00:00:00Z\n"


@pytest.fixture
def server():
    routes = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            r = routes.get(self.path)
            if r is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, ctype, body = r[:3]
            self.send_response(status)
            if status in (301, 302):
                self.send_header("Location", ctype)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    routes["host"] = f"127.0.0.1:{httpd.server_port}"
    yield routes
    httpd.shutdown()
    httpd.server_close()


def ok(body=FILE, ctype="text/plain; charset=utf-8"):
    return (200, ctype, body.encode())


def run(server, **kw):
    return check_domain(server["host"], scheme="http", now=NOW, delay=0, **kw)


def test_fetch_200_and_404(server):
    server["/a"] = ok()
    r = fetch(f"http://{server['host']}/a")
    assert r.status == 200 and r.body == FILE.encode() and not r.redirected
    assert fetch(f"http://{server['host']}/missing").not_found


def test_fetch_network_error():
    r = fetch("http://127.0.0.1:1/x", timeout=2)
    assert r.error and r.status is None


def test_valid_domain(server):
    server["/.well-known/security.txt"] = ok()
    res = run(server)
    assert res.valid and res.exit_code == 0
    assert res.legacy.fetched.not_found and not res.legacy.found
    d = res.to_dict()
    assert d["well_known"]["status"] == 200 and d["legacy"]["not_found"]


def test_missing(server):
    res = run(server)
    assert not res.valid and res.exit_code == 1
    assert res.well_known.fetched.not_found


def test_wrong_content_type(server):
    server["/.well-known/security.txt"] = ok(ctype="text/html")
    res = run(server)
    assert res.exit_code == 1
    assert "content-type" in {i.code for i in res.well_known.issues}


def test_missing_charset_is_warning(server):
    server["/.well-known/security.txt"] = ok(ctype="text/plain")
    res = run(server)
    assert res.valid
    assert "charset" in {i.code for i in res.well_known.issues if i.level == "warning"}


def test_legacy_redirect_noted(server):
    server["/.well-known/security.txt"] = ok()
    server["/security.txt"] = (302, "/.well-known/security.txt", b"")
    res = run(server)
    assert res.legacy.fetched.redirected and res.legacy.valid
    assert res.to_dict()["legacy_redirects"] is True


def test_https_enforced_in_production_mode(server):
    from security_txt.net import Fetched, build_report
    f = Fetched("http://x/.well-known/security.txt", "http://x/.well-known/security.txt", 200,
                "text/plain; charset=utf-8", FILE.encode())
    rep = build_report("/.well-known/security.txt", f, NOW, require_https=True)
    assert "not-https" in {i.code for i in rep.issues}


def test_invalid_utf8(server):
    server["/.well-known/security.txt"] = (200, "text/plain; charset=utf-8", b"\xff\xfe" + FILE.encode())
    res = run(server)
    assert "encoding" in {i.code for i in res.well_known.issues}


def test_watch_expiry(server):
    server["/.well-known/security.txt"] = ok()
    assert run(server, watch_days=100).exit_code == 0
    res = run(server, watch_days=300)
    assert res.expiry_soon and res.exit_code == 1


def test_cli_exit_codes(server, capsys):
    host = server["host"]
    args = ["check", host, "--scheme", "http", "--delay", "0"]
    assert main(args) == 1  # 404
    server["/.well-known/security.txt"] = ok(
        FILE.replace("2026-12-31", "2099-12-31").replace("Expires", "Expires"))
    # far-future expiry is only a warning
    assert main(args) == 0
    capsys.readouterr()
    assert main(args + ["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] and data["well_known"]["status"] == 200
    assert main(args + ["--watch-expiry", "99999"]) == 1
    assert main(["check", "127.0.0.1:1", "--scheme", "http", "--delay", "0", "--timeout", "2"]) == 2
    assert main(["check"]) == 2
    assert main(["check", "  "]) == 2
