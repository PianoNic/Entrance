"""Shared HTTP client: connection reuse, token POST parsing and timeouts. No network - httpx is mocked."""

import httpx
import pytest

from entrance import _foci, _http


@pytest.fixture
def mock_client(monkeypatch):
    def install(handler):
        c = httpx.Client(transport=httpx.MockTransport(handler))
        monkeypatch.setattr(_http, "_client", c)
        return c

    yield install
    monkeypatch.setattr(_http, "_client", None)


def test_client_is_shared_and_has_bounded_connect_timeout(monkeypatch):
    monkeypatch.setattr(_http, "_client", None)
    a, b = _http.client(), _http.client()
    assert a is b
    assert a.timeout.connect == _http.CONNECT_TIMEOUT < a.timeout.read
    _http.close()
    assert _http.client() is not a
    _http.close()


def test_post_token_returns_success_and_error_bodies(mock_client):
    seen = []

    def handler(req):
        seen.append(req.content.decode())
        if b"bad" in req.content:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "gone"})
        return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})

    mock_client(handler)
    assert _foci._post_token("https://x/token", {"refresh_token": "ok"})["access_token"] == "t"
    assert (
        _foci._post_token("https://x/token", {"refresh_token": "bad"})["error"] == "invalid_grant"
    )
    assert len(seen) == 2


def test_post_token_wraps_transport_errors_and_non_json(mock_client):
    def boom(req):
        raise httpx.ConnectTimeout("timed out")

    mock_client(boom)
    with pytest.raises(RuntimeError, match="Token endpoint error"):
        _foci._post_token("https://x/token", {})

    mock_client(lambda req: httpx.Response(502, text="<html>bad gateway</html>"))
    with pytest.raises(RuntimeError, match="HTTP 502"):
        _foci._post_token("https://x/token", {})


def test_warm_up_never_raises(mock_client):
    def boom(req):
        raise httpx.ConnectError("down")

    mock_client(boom)
    _http.warm_up(["https://x/"])
