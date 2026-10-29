"""Number-matching push: BeginAuth surfaces the tap number, EndAuth is polled to
approval / denial / timeout, and the existing TOTP MFA path is untouched. No
network - the curl_cffi session is faked and no real tokens are used."""

import pytest

import entrance
from entrance import _client, _push
from entrance._push import _PushRequest, run_push_challenge

CFG = {
    "urlBeginAuth": "https://login.microsoftonline.com/common/SAS/BeginAuth",
    "urlEndAuth": "https://login.microsoftonline.com/common/SAS/EndAuth",
    "urlPost": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
    "sCtx": "ctx0",
    "sFT": "ft0",
    "sPOST_Username": "you@school.ch",
}


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class _FakeSession:
    """Returns the queued responses in order; records every call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def post(self, url, json=None, data=None, headers=None, allow_redirects=None):
        self.calls.append({"url": url, "json": json, "data": data})
        return _Resp(self._responses.pop(0))


def _events():
    out = []
    return out, out.append


# --- run_push_challenge -----------------------------------------------------
def test_number_is_surfaced_then_approved(monkeypatch):
    monkeypatch.setattr(_push.time, "sleep", lambda s: None)
    c = _FakeSession(
        [
            {"Success": True, "Entropy": 42, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"},
            {"Success": False, "Retry": True, "ResultValue": "AuthenticationPending"},
            {"Success": True, "Ctx": "c2", "FlowToken": "f2"},
        ]
    )
    log, on_event = _events()
    req = _PushRequest(on_event=on_event, timeout=120, interval=0)

    ctx, ft = run_push_challenge(c, CFG, _push.PUSH_METHOD, {}, req)

    assert (ctx, ft) == ("c2", "f2")
    assert [e.state for e in log] == [_push.NUMBER_MATCHING, _push.PENDING, _push.APPROVED]
    assert log[0].number == "42"
    assert "42" in log[0].message
    assert log[0].expires_in == 120
    # BeginAuth then two EndAuth polls, PollCount incrementing.
    assert c.calls[0]["json"]["Method"] == "BeginAuth"
    assert c.calls[1]["json"] == {
        "AuthMethodId": _push.PUSH_METHOD,
        "Method": "EndAuth",
        "ctx": "c1",
        "flowToken": "f1",
        "SessionId": "S",
        "PollCount": 1,
    }
    assert c.calls[2]["json"]["PollCount"] == 2
    # No OTP is ever sent on the push path.
    assert all("AdditionalAuthData" not in call["json"] for call in c.calls)


def test_denied_raises_and_emits(monkeypatch):
    monkeypatch.setattr(_push.time, "sleep", lambda s: None)
    c = _FakeSession(
        [
            {"Success": True, "Entropy": 7, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"},
            {"Success": False, "Retry": False, "ResultValue": "PhoneAppDenied"},
        ]
    )
    log, on_event = _events()
    req = _PushRequest(on_event=on_event, timeout=120, interval=0)

    with pytest.raises(_push.PushError) as e:
        run_push_challenge(c, CFG, _push.PUSH_METHOD, {}, req)

    assert e.value.state == _push.DENIED
    assert log[-1].state == _push.DENIED
    assert "PhoneAppDenied" in log[-1].message


def test_timeout_raises_and_emits(monkeypatch):
    monkeypatch.setattr(_push.time, "sleep", lambda s: None)
    # timeout=0: the number is surfaced, then the poll loop never runs.
    c = _FakeSession(
        [{"Success": True, "Entropy": 13, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"}]
    )
    log, on_event = _events()
    req = _PushRequest(on_event=on_event, timeout=0, interval=0)

    with pytest.raises(_push.PushError) as e:
        run_push_challenge(c, CFG, _push.PUSH_METHOD, {}, req)

    assert e.value.state == _push.TIMED_OUT
    assert [e.state for e in log] == [_push.NUMBER_MATCHING, _push.TIMED_OUT]


def test_no_entropy_means_plain_approval():
    # Older tenants / no number matching: Entropy missing or 0 -> number is None.
    c = _FakeSession(
        [{"Success": True, "Entropy": 0, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"}]
    )
    log, on_event = _events()
    req = _PushRequest(on_event=on_event, timeout=0, interval=0)

    with pytest.raises(_push.PushError):
        run_push_challenge(c, CFG, _push.PUSH_METHOD, {}, req)

    assert log[0].state == _push.NUMBER_MATCHING
    assert log[0].number is None
    assert "Authenticator" in log[0].message


def test_begin_auth_failure_raises():
    c = _FakeSession([{"Success": False, "Message": "nope"}])
    req = _PushRequest(timeout=120, interval=0)
    with pytest.raises(_push.PushError, match="BeginAuth failed"):
        run_push_challenge(c, CFG, _push.PUSH_METHOD, {}, req)


# --- _handle_mfa push branch ------------------------------------------------
def test_handle_mfa_push_requires_push_method():
    cfg = dict(CFG, arrUserProofs=[{"authMethodId": "PhoneAppOTP"}])
    with pytest.raises(entrance.MfaRequired, match="No Authenticator push method"):
        _client._handle_mfa(_FakeSession([]), cfg, None, None, push_req=_PushRequest())


def test_handle_mfa_push_runs_challenge_then_process(monkeypatch):
    cfg = dict(CFG, arrUserProofs=[{"authMethodId": "PhoneAppNotification"}], canary="CAN")
    monkeypatch.setattr(
        _client, "run_push_challenge", lambda c, cfg, method, hdr, req: ("CTX", "FT")
    )
    c = _FakeSession([{"redirect": "ok"}])

    _client._handle_mfa(c, cfg, None, None, push_req=_PushRequest())

    sent = c.calls[-1]["data"]
    assert sent["flowToken"] == "FT" and sent["request"] == "CTX"
    assert sent["mfaAuthMethod"] == _push.PUSH_METHOD
    assert "otc" not in sent  # push carries no one-time code


# --- the existing TOTP path still works unchanged ---------------------------
def test_totp_mfa_path_unchanged():
    cfg = dict(CFG, arrUserProofs=[{"authMethodId": "PhoneAppOTP"}], canary="CAN")
    c = _FakeSession(
        [
            {"Success": True, "Ctx": "c1", "FlowToken": "f1", "SessionId": "S"},  # BeginAuth
            {"Success": True, "ResultValue": "Success", "Ctx": "c2", "FlowToken": "f2"},  # EndAuth
            {"redirect": "ok"},  # ProcessAuth
        ]
    )
    _client._handle_mfa(c, cfg, lambda: "123456", None)

    assert c.calls[0]["json"]["Method"] == "BeginAuth"
    assert c.calls[1]["json"]["AdditionalAuthData"] == "123456"
    assert c.calls[1]["json"]["PollCount"] == 1
    assert c.calls[2]["data"]["otc"] == "123456"  # OTP still submitted on ProcessAuth


# --- push_login wiring + public surface -------------------------------------
def test_push_login_wires_foci_login(monkeypatch):
    import entrance._foci as foci

    captured = {}
    monkeypatch.setattr(foci, "foci_login", lambda *a, **k: captured.update(a=a, k=k) or "BROKER")

    cb = lambda ev: None  # noqa: E731
    out = entrance.push_login("you@school.ch", "pw", on_event=cb, timeout=30, interval=1)

    assert out == "BROKER"
    assert captured["k"]["push"] is True
    assert captured["k"]["on_push"] is cb
    assert captured["k"]["push_timeout"] == 30
    assert captured["k"]["push_interval"] == 1
    assert captured["a"] == ("you@school.ch", "pw")


def test_public_surface():
    assert callable(entrance.push_login)
    assert issubclass(entrance.PushError, Exception)
    assert entrance.PushEvent(entrance.NUMBER_MATCHING, number="42").number == "42"
    for state in ("PENDING", "APPROVED", "DENIED", "TIMED_OUT", "NUMBER_MATCHING"):
        assert isinstance(getattr(entrance, state), str)


def test_login_keeps_old_signature_and_adds_push():
    import inspect

    params = inspect.signature(entrance.login).parameters
    assert "totp_secret" in params and "totp_code" in params  # unchanged
    assert params["push"].default is False  # new, off by default
