"""Shared HTTP client, against a real server on localhost: connection reuse, redirects, token POST
parsing, retries and timeouts. No outside network."""

import gzip
import http.server
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from entrance import _foci, _http


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status=200, body=b"", **headers):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        srv = self.server
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        srv.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "body": body,
                "headers": self.headers,
                "conn": self.client_address,
            }
        )
        if self.path == "/redirect-other-host":
            self._reply(302, Location=f"http://localhost:{srv.server_address[1]}/landed")
        elif self.path == "/redirect":
            self._reply(302, Location="/landed")
        elif self.path == "/gzip":
            self._reply(200, gzip.compress(b"unpacked"), Content_Encoding="gzip")
        elif self.path == "/drop":  # took the request, then died without answering
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
        elif self.path == "/bad-gateway":
            self._reply(502, b"<html>bad gateway</html>")
        elif b"bad" in body:
            self._reply(400, b'{"error":"invalid_grant","error_description":"gone"}')
        else:
            self._reply(200, b'{"access_token":"t","expires_in":3600}', X_Mixed_Case="yes")

    do_GET = do_POST = do_HEAD = _handle

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    srv.seen = []
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture(autouse=True)
def fresh_client():
    _http.close()
    yield
    _http.close()


def closed_port_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}/"


def test_client_is_shared_and_rebuilt_after_close():
    a, b = _http.client(), _http.client()
    assert a is b
    assert _http.CONNECT_TIMEOUT < _http.READ_TIMEOUT
    _http.close()
    assert _http.client() is not a


def test_sequential_requests_reuse_one_connection(server):
    for _ in range(3):
        _http.client().request("GET", server.url + "/")
    assert len({r["conn"] for r in server.seen}) == 1


def test_threads_can_share_the_client(server):
    with ThreadPoolExecutor(20) as pool:
        got = list(pool.map(lambda _: _http.client().request("GET", server.url), range(60)))
    assert {r.status_code for r in got} == {200}


def test_response_surface(server):
    r = _http.client().request("GET", server.url + "/")
    assert (r.status_code, r.reason_phrase) == (200, "OK")
    assert r.json()["access_token"] == "t" and "access_token" in r.text
    assert r.headers.get("x-mixed-case") == r.headers["X-MIXED-CASE"] == "yes"
    assert "X-Mixed-Case" in r.headers and r.headers.get("nope", "d") == "d"


def test_gzip_is_decoded(server):
    assert _http.client().request("GET", server.url + "/gzip").content == b"unpacked"


def test_empty_post_sends_content_length(server):
    # login.microsoftonline.com answers 411 without it
    _http.client().request("POST", server.url + "/")
    assert server.seen[0]["headers"]["Content-Length"] == "0"


def test_form_post_is_urlencoded(server):
    _http.client().post(server.url + "/", data={"a": "b c"})
    assert server.seen[0]["body"] == b"a=b+c"
    assert server.seen[0]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_redirects_are_opt_in(server):
    r = _http.client().request("GET", server.url + "/redirect")
    assert r.status_code == 302 and r.headers["Location"] == "/landed"
    r = _http.client().request("GET", server.url + "/redirect", follow_redirects=True)
    assert r.status_code == 200 and server.seen[-1]["path"] == "/landed"


def test_redirect_to_another_host_drops_the_bearer_token(server):
    _http.client().request(
        "GET",
        server.url + "/redirect-other-host",
        headers={"Authorization": "Bearer secret"},
        follow_redirects=True,
    )
    assert server.seen[0]["headers"]["Authorization"] == "Bearer secret"
    assert server.seen[-1]["path"] == "/landed"
    assert server.seen[-1]["headers"]["Authorization"] is None


def test_refused_connection_retries_then_raises():
    with pytest.raises(_http.HTTPError):
        _http.client().request("GET", closed_port_url())


def test_connection_lost_after_sending_is_not_resent(server):
    # A resend here could deliver a mail or a chat message twice.
    with pytest.raises(_http.HTTPError):
        _http.client().request("POST", server.url + "/drop", content=b"send-mail", timeout=5)
    assert len(server.seen) == 1


def test_post_token_returns_success_and_error_bodies(server):
    assert _foci._post_token(server.url, {"refresh_token": "ok"})["access_token"] == "t"
    assert _foci._post_token(server.url, {"refresh_token": "bad"})["error"] == "invalid_grant"
    assert len(server.seen) == 2


def test_post_token_wraps_transport_errors_and_non_json(server):
    with pytest.raises(RuntimeError, match="Token endpoint error"):
        _foci._post_token(closed_port_url(), {})
    with pytest.raises(RuntimeError, match="HTTP 502"):
        _foci._post_token(server.url + "/bad-gateway", {})


def test_warm_up_never_raises():
    _http.warm_up([closed_port_url()])
