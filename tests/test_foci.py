"""FOCI broker + foci_login: token caching/rotation, atomic persistence,
store reuse and dead-store handling. No network - the token endpoint is faked."""

import pytest

import entrance
from entrance import _foci


def test_write_secret_is_atomic_and_private(tmp_path):
    p = tmp_path / "frt"
    _foci.write_secret(str(p), "one")
    _foci.write_secret(str(p), "two")
    assert _foci.read_secret(str(p)) == "two"
    assert [f.name for f in tmp_path.iterdir()] == ["frt"]  # no temp file left behind
    assert _foci.read_secret(str(tmp_path / "missing")) is None


def test_broker_caches_per_client_and_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(
        _foci,
        "_post_token",
        lambda url, data: (
            calls.append((data["client_id"], data["scope"]))
            or {"access_token": data["client_id"][:4] + ":" + data["scope"][:4], "expires_in": 3600}
        ),
    )
    b = entrance.Broker("frt")
    assert b("clientA") == "clie:http"  # default GRAPH_SCOPE
    assert b("clientA") == "clie:http"  # cached - no second call
    assert b("clientA", "api://x/.default") == "clie:api:"  # different scope -> new token
    assert len(calls) == 2


def test_broker_persists_rotated_token(monkeypatch, tmp_path):
    store = str(tmp_path / "frt")
    monkeypatch.setattr(
        _foci,
        "_post_token",
        lambda url, data: {"access_token": "at", "refresh_token": "rotated", "expires_in": 3600},
    )
    b = entrance.Broker("orig", store=store)
    assert b("client") == "at"
    assert _foci.read_secret(store) == "rotated" and b.refresh_token == "rotated"


def test_broker_raises_tokenerror_on_refused_grant(monkeypatch):
    monkeypatch.setattr(
        _foci,
        "_post_token",
        lambda url, data: {"error": "invalid_grant", "error_description": "expired"},
    )
    with pytest.raises(entrance.TokenError) as e:
        entrance.Broker("dead")("client")
    assert e.value.error == "invalid_grant"


def test_foci_login_reuses_store_without_signin(monkeypatch, tmp_path):
    store = tmp_path / "frt"
    store.write_text("saved")
    monkeypatch.setattr(_foci, "_post_token", lambda url, data: {"access_token": "at"})
    # entrance.login must NOT be called when the store is live
    import entrance._client as client

    monkeypatch.setattr(client, "login", lambda *a, **k: pytest.fail("should not sign in"))
    broker = entrance.foci_login(frt_store=str(store))
    assert broker("whatever") == "at"


def test_foci_login_drops_dead_store(monkeypatch, tmp_path):
    store = tmp_path / "frt"
    store.write_text("dead")
    monkeypatch.setattr(
        _foci,
        "_post_token",
        lambda url, data: {"error": "invalid_grant", "error_description": "revoked"},
    )
    assert _foci._broker_from_store(str(store), "common", _foci.OFFICEHOME) is None
    assert not store.exists()  # a dead token is removed


def test_foci_login_signs_in_and_persists(monkeypatch, tmp_path):
    store = tmp_path / "frt"
    captured = {}

    def fake_login(url, **kw):
        captured["url"] = url
        return {"code": "CODE"}

    import entrance._client as client

    monkeypatch.setattr(client, "login", fake_login)
    monkeypatch.setattr(
        _foci, "_post_token", lambda url, data: {"refresh_token": "NEWFRT", "access_token": "x"}
    )
    broker = entrance.foci_login("you@x.ch", "pw", frt_store=str(store), cookies=None)
    assert isinstance(broker, entrance.Broker)
    assert broker.refresh_token == "NEWFRT"
    assert _foci.read_secret(str(store)) == "NEWFRT"
    assert f"client_id={_foci.OFFICEHOME}" in captured["url"]


def test_foci_login_raises_without_code(monkeypatch, tmp_path):
    import entrance._client as client

    monkeypatch.setattr(client, "login", lambda *a, **k: {"session_cookies": []})
    with pytest.raises(entrance.TokenError, match="no_code|No authorization code"):
        entrance.foci_login("you@x.ch", "pw", frt_store=None, cookies=None)
