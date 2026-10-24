"""browser_login: loopback and paste modes, end to end on localhost - the
"browser" is a function that sends the redirect itself. No Microsoft involved."""

import socket
import threading
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

import entrance
from entrance import _browser, _client

AUTH = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
NATIVE = "https://login.microsoftonline.com/common/oauth2/nativeclient"


def _authorize(redirect_uri, state="st-1"):
    query = {"client_id": "cid", "response_type": "code", "redirect_uri": redirect_uri}
    return AUTH + "?" + urlencode({**query, "state": state})


def _fake_browser(params):
    """Opens the authorize URL by sending the redirect Microsoft would send."""
    seen = {}

    def open_browser(url):
        q = dict(parse_qsl(urlsplit(url).query))
        seen["redirect_uri"] = q["redirect_uri"]
        target = q["redirect_uri"] + "?" + urlencode(params)

        def hit():
            with urllib.request.urlopen(target, timeout=5) as r:
                seen["page"] = r.read()

        seen["thread"] = threading.Thread(target=hit, daemon=True)
        seen["thread"].start()
        return True

    return open_browser, seen


def test_is_loopback():
    assert entrance.is_loopback("http://localhost")
    assert entrance.is_loopback("http://127.0.0.1:8400/cb")
    assert not entrance.is_loopback("https://localhost")  # https can't be served
    assert not entrance.is_loopback(NATIVE)
    assert not entrance.is_loopback(None)


def test_loopback_fills_free_port_and_catches_code():
    open_browser, seen = _fake_browser({"code": "the-code", "state": "st-1"})
    res = entrance.browser_login(
        _authorize("http://localhost"), open_browser=open_browser, timeout=5
    )
    assert res["code"] == "the-code" and res["state"] == "st-1" and res["mode"] == "loopback"
    port = urlsplit(seen["redirect_uri"]).port
    assert port and res["redirect_uri"] == f"http://localhost:{port}"
    seen["thread"].join(5)
    assert b"Signed in" in seen["page"]
    assert res["session_cookies"] == [] and res["tokens"] is None


def test_loopback_keeps_explicit_port_and_path():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ru = f"http://127.0.0.1:{port}/callback"
    open_browser, seen = _fake_browser({"code": "c2", "state": "st-1"})
    res = entrance.browser_login(_authorize(ru), open_browser=open_browser, timeout=5)
    assert seen["redirect_uri"] == ru and res["code"] == "c2"


def test_loopback_error_raises():
    open_browser, seen = _fake_browser({"error": "access_denied", "error_description": "nope"})
    with pytest.raises(entrance.LoginFailed, match="access_denied: nope"):
        entrance.browser_login(_authorize("http://localhost"), open_browser=open_browser, timeout=5)
    seen["thread"].join(5)
    assert b"failed" in seen["page"]


def test_loopback_state_mismatch_raises():
    open_browser, _ = _fake_browser({"code": "c", "state": "forged"})
    with pytest.raises(entrance.LoginFailed, match="State mismatch"):
        entrance.browser_login(_authorize("http://localhost"), open_browser=open_browser, timeout=5)


def test_loopback_times_out():
    with pytest.raises(entrance.LoginFailed, match="within 1s"):
        entrance.browser_login(
            _authorize("http://localhost"), open_browser=lambda url: True, timeout=1
        )


@pytest.mark.parametrize(
    "pasted",
    [
        NATIVE + "?code=pc&state=st-1&session_state=x",
        "  " + NATIVE + "#code=pc&state=st-1  ",  # response_mode=fragment, whitespace
        "pc",  # just the code
        "code=pc&state=st-1",
    ],
)
def test_paste_mode_accepts_url_fragment_or_bare_code(pasted):
    res = entrance.browser_login(
        _authorize(NATIVE), open_browser=lambda url: True, prompt=lambda text: pasted
    )
    assert res["code"] == "pc" and res["mode"] == "paste" and res["state"] == "st-1"


def test_paste_mode_error_and_missing_code():
    with pytest.raises(entrance.LoginFailed, match="invalid_request"):
        entrance.browser_login(
            _authorize(NATIVE),
            open_browser=lambda url: True,
            prompt=lambda text: NATIVE + "?error=invalid_request&error_description=bad",
        )
    with pytest.raises(entrance.LoginFailed, match="No authorization code"):
        entrance.browser_login(
            _authorize(NATIVE), open_browser=lambda url: True, prompt=lambda text: NATIVE
        )


def test_browser_failure_still_prompts():
    def boom(url):
        raise OSError("no browser")

    res = entrance.browser_login(_authorize(NATIVE), open_browser=boom, prompt=lambda t: "pc")
    assert res["code"] == "pc"


def test_exchange_uses_the_redirect_uri_actually_sent(monkeypatch):
    seen = {}

    def fake_exchange(c, code, xchg):
        seen.update(xchg, code=code)
        return {"access_token": "at"}

    monkeypatch.setattr(_client, "_exchange", fake_exchange)
    open_browser, sent = _fake_browser({"code": "c", "state": "st-1"})
    res = entrance.browser_login(
        _authorize("http://localhost"),
        code_verifier="v",
        token_url="https://x/token",
        open_browser=open_browser,
        timeout=5,
    )
    assert res["access_token"] == "at"
    assert seen["redirect_uri"] == sent["redirect_uri"] and seen["code_verifier"] == "v"
    assert seen["client_id"] == "cid"


def test_login_interactive_falls_back_to_browser(monkeypatch):
    def headless(*a, **k):
        raise entrance.MfaRequired("push only")

    calls = {}
    monkeypatch.setattr(_client, "_headless", headless)
    monkeypatch.setattr(
        _browser, "browser_login", lambda url, **kw: calls.update(kw, url=url) or {"code": "b"}
    )
    res = entrance.login(_authorize(NATIVE), code_verifier="v", interactive=True)
    assert res == {"code": "b"}
    assert calls["code_verifier"] == "v" and calls["url"].startswith(AUTH)
    with pytest.raises(entrance.MfaRequired):
        entrance.login(_authorize(NATIVE))  # not interactive: the headless error surfaces
    with pytest.raises(ValueError):
        entrance.login(_authorize(NATIVE), interactive=True, ms_redirect=True)


def test_login_interactive_always_skips_headless(monkeypatch):
    # "always" = full manual browser sign-in, never attempt headless
    monkeypatch.setattr(
        _client, "_headless", lambda *a, **k: pytest.fail("headless must be skipped")
    )
    calls = {}
    monkeypatch.setattr(
        _browser, "browser_login", lambda url, **kw: calls.update(url=url) or {"code": "manual"}
    )
    res = entrance.login(_authorize(NATIVE), username="u", password="p", interactive="always")
    assert res == {"code": "manual"} and calls["url"].startswith(AUTH)


def test_login_interactive_without_credentials_goes_to_browser(monkeypatch, capsys):
    # no username/password: the browser was the intended path, so no scary message
    monkeypatch.setattr(_browser, "browser_login", lambda url, **kw: {"code": "b"})
    assert entrance.login(_authorize(NATIVE), interactive=True) == {"code": "b"}
    assert "didn't finish" not in capsys.readouterr().err
