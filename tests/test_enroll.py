"""enroll_totp(): drives the My Sign-Ins Security-info API. The four POSTs and
the token sign-in are faked, so no network and no account changes - we assert
the exact request shapes captured from the real portal."""

import json

import pyotp
import pytest

import entrance
from entrance import _enroll

SECRET = "JBSWY3DPEHPK3PXP"


class FakeApiSession:
    """Stands in for the curl_cffi session used by _Api: records POSTs and
    answers from a scripted table keyed by path."""

    def __init__(self):
        self.headers = {}
        self.calls = []
        self.answers = {
            "session/authorize": {"isAuthorized": True, "sessionCtxV2": "CTX", "ErrorCode": 0},
            "authenticationmethods/initializemobileapp": {
                "SecretKey": SECRET,
                "AccountName": "Example:you@school.ch",
                "ErrorCode": 0,
            },
            "authenticationmethods/new": {"VerificationContext": "VCTX", "ErrorCode": 0},
            "authenticationmethods/verify": {"VerificationState": 2, "ErrorCode": 0},
        }

    def post(self, url, data=b""):
        path = url.split("/api/", 1)[1]
        body = json.loads(data) if data else None
        self.calls.append(
            {"path": path, "body": body, "sessionctxv2": self.headers.get("sessionctxv2")}
        )

        class R:
            status_code = 200

            def __init__(self, payload):
                self._p = payload

            def json(self):
                return self._p

        return R(self.answers[path])


@pytest.fixture
def faked(monkeypatch):
    sess = FakeApiSession()
    monkeypatch.setattr(_enroll.requests, "Session", lambda **k: sess)
    monkeypatch.setattr(_enroll, "_portal_token", lambda *a, **k: "ACCESS.TOKEN.aud19db86c3")
    return sess


def test_enroll_totp_happy_path(faked, monkeypatch):
    monkeypatch.setattr(_enroll.time, "time", lambda: 1000.0)  # mid-window, no sleep
    dev = entrance.enroll_totp("you@school.ch", "pw", totp_secret="OLDSECRET")
    assert isinstance(dev, entrance.TotpDevice)
    assert dev.secret == SECRET
    assert dev.account_name == "Example:you@school.ch"

    paths = [c["path"] for c in faked.calls]
    assert paths == [
        "session/authorize",
        "authenticationmethods/initializemobileapp",
        "authenticationmethods/new",
        "authenticationmethods/verify",
    ]
    c = {c["path"]: c for c in faked.calls}
    # initialize asks for software-OATH (type 3)
    assert c["authenticationmethods/initializemobileapp"]["body"] == {"securityInfoType": 3}
    # /new carries the secret as a JSON *string* under Data
    new_body = c["authenticationmethods/new"]["body"]
    assert new_body["Type"] == 3
    assert json.loads(new_body["Data"])["secretKey"] == SECRET
    # /verify sends a real code for the new secret + the context from /new
    v = c["authenticationmethods/verify"]["body"]
    assert v["VerificationContext"] == "VCTX" and v["Type"] == 3
    assert v["VerificationData"] == pyotp.TOTP(SECRET).now()
    # the session context from session/authorize is sent on the later calls, not before
    assert c["session/authorize"]["sessionctxv2"] is None
    assert c["authenticationmethods/initializemobileapp"]["sessionctxv2"] == "CTX"


def test_required_headers_are_set(faked, monkeypatch):
    monkeypatch.setattr(_enroll.time, "time", lambda: 1000.0)
    entrance.enroll_totp("you@school.ch", "pw", totp_secret="OLD")
    h = faked.headers
    assert h["Authorization"] == "Bearer ACCESS.TOKEN.aud19db86c3"
    assert h["ajaxrequest"] == "true"
    assert h["Content-Type"] == "application/json"


def test_enroll_raises_on_error_code(faked, monkeypatch):
    monkeypatch.setattr(_enroll.time, "time", lambda: 1000.0)
    faked.answers[
        "initializemobileapp" if False else "authenticationmethods/initializemobileapp"
    ] = {
        "SecretKey": None,
        "ErrorCode": 42,
        "ErrorType": "SomethingBad",
    }
    with pytest.raises(entrance.EnrollmentError, match="ErrorCode 42"):
        entrance.enroll_totp("you@school.ch", "pw", totp_secret="OLD")


def test_enroll_raises_when_not_activated(faked, monkeypatch):
    monkeypatch.setattr(_enroll.time, "time", lambda: 1000.0)
    faked.answers["authenticationmethods/verify"] = {"VerificationState": 1, "ErrorCode": 0}
    with pytest.raises(entrance.EnrollmentError, match="did not activate"):
        entrance.enroll_totp("you@school.ch", "pw", totp_secret="OLD")


def test_portal_token_builds_ngcmfa_authorize_url_then_exchanges(monkeypatch):
    captured = {}

    def fake_login(url, **kw):
        captured["url"] = url
        captured["kw"] = kw
        return {"code": "THECODE", "code_verifier": "v"}  # login yields a code

    # login is imported inside _portal_token from entrance._client; patch there
    import entrance._client as client

    monkeypatch.setattr(client, "login", fake_login)
    monkeypatch.setattr(_enroll, "_exchange_spa", lambda code, verifier, tenant: f"TOKEN:{code}")
    tok = _enroll._portal_token("you@school.ch", "pw", "SEC", None, "common", None, False)
    assert tok == "TOKEN:THECODE"
    assert "client_id=19db86c3-b2b9-44cc-b339-36da233a3be2" in captured["url"]
    assert "ngcmfa" in captured["url"]
    assert captured["kw"]["redirect_uri"] == _enroll.PORTAL_REDIRECT
    assert captured["kw"]["totp_secret"] == "SEC"
    # no token_url: enroll does its own SPA exchange (Origin header), not login's
    assert "token_url" not in captured["kw"]


def test_exchange_spa_sends_origin_and_app_scope(monkeypatch):
    seen = {}

    class S:
        headers = {}

        def update(self, d):
            self.headers.update(d)

    class Sess:
        def __init__(self):
            self.headers = S()

        def post(self, url, data=None, headers=None):
            seen["url"] = url
            seen["data"] = data
            seen["headers"] = headers

            class R:
                status_code = 200

                def json(self):
                    return {"access_token": "AT19db86c3"}

            return R()

    monkeypatch.setattr(_enroll.requests, "Session", lambda **k: Sess())
    tok = _enroll._exchange_spa("thecode", "theverifier", "common")
    assert tok == "AT19db86c3"
    assert seen["headers"]["Origin"] == _enroll.PORTAL_REDIRECT  # SPA cross-origin
    assert seen["data"]["scope"] == f"{_enroll.PORTAL_CLIENT}/.default"
    assert seen["data"]["code"] == "thecode"


def test_exchange_spa_raises_on_error(monkeypatch):
    class Sess:
        def __init__(self):
            self.headers = type("H", (), {"update": lambda self, d: None})()

        def post(self, *a, **k):
            class R:
                status_code = 400

                def json(self):
                    return {"error": "invalid_grant", "error_description": "bad code"}

            return R()

    monkeypatch.setattr(_enroll.requests, "Session", lambda **k: Sess())
    with pytest.raises(entrance.EnrollmentError, match="bad code"):
        _enroll._exchange_spa("c", "v", "common")
