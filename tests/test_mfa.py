"""Interactive MFA hook (`mfa=<MfaPrompt>`): method choice, push, authenticator
code with retries, switching, and the distinct failure types. The whole Microsoft
sign-in is faked at the curl_cffi session - no network."""

import json
import logging
import traceback

import pytest

import entrance
from entrance import MfaCancelled, MfaPrompt, MfaSwitch, Secret, _client, _push

PASSWORD = "S3cret-pw-9f2c1"
AUTHORIZE = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    "?client_id=cid&redirect_uri=https%3A%2F%2Fcb.example%2Fcb&state=ST&response_type=code"
)
CALLBACK = "https://cb.example/cb?code=THECODE&state=ST"
BASE = "https://login.microsoftonline.com/common"


class Resp:
    def __init__(self, status=200, text="", headers=None, url=AUTHORIZE, data=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = url
        self._data = data

    def json(self):
        return self._data


def page(**cfg):
    base = {"sFT": "ft", "sCtx": "ctx", "canary": "can", "urlPost": f"{BASE}/login"}
    base.update(cfg)
    return Resp(text="<html><script>$Config=" + json.dumps(base) + ";</script></html>")


def creds_page(**extra):
    return page(urlGetCredentialType=f"{BASE}/GetCredentialType", **extra)


def mfa_page(*ids):
    return page(
        urlPost=f"{BASE}/ProcessAuth",
        urlBeginAuth=f"{BASE}/SAS/BeginAuth",
        urlEndAuth=f"{BASE}/SAS/EndAuth",
        arrUserProofs=[{"authMethodId": i} for i in ids],
        sPOST_Username="u@school.ch",
    )


def redirect(location):
    return Resp(302, headers={"location": location})


class FakeSession:
    """Routes by URL. `login_result` is what the password POST returns; BeginAuth /
    EndAuth answers come from queues; ProcessAuth finishes at the callback."""

    last = None

    def __init__(self, *a, **k):
        self.headers = {}
        self.cookies = type("J", (), {"jar": [], "set": lambda *a, **k: None})()
        self.gct = {"Credentials": {}, "IfExistsResult": 0}
        self.login_result = redirect(CALLBACK)
        self.begin = []
        self.end = []
        self.calls = []
        FakeSession.last = self

    def get(self, url, **kw):
        self.calls.append(("GET", url, None))
        return creds_page()

    def post(self, url, json=None, data=None, headers=None, allow_redirects=None):
        self.calls.append(("POST", url, json if json is not None else data))
        if url.endswith("GetCredentialType"):
            return Resp(data=self.gct)
        if url.endswith("BeginAuth"):
            return Resp(data=self.begin.pop(0))
        if url.endswith("EndAuth"):
            return Resp(data=self.end.pop(0))
        if url.endswith("ProcessAuth"):
            return redirect(CALLBACK)
        return self.login_result

    def sent(self, suffix):
        return [p for m, u, p in self.calls if u.endswith(suffix)]


def session(monkeypatch, login_result=None, gct=None, begin=(), end=()):
    class S(FakeSession):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            if login_result is not None:
                self.login_result = login_result
            if gct is not None:
                self.gct = gct
            self.begin = list(begin)
            self.end = list(end)

    monkeypatch.setattr(_client.requests, "Session", S)
    monkeypatch.setattr(_push.time, "sleep", lambda s: None)
    return S


def mfa_session(monkeypatch, *ids, begin=(), end=()):
    return session(monkeypatch, mfa_page(*ids), begin=begin, end=end)


class Prompt(MfaPrompt):
    def __init__(self, methods=("push",), codes=("123456",), switch_after=None, retry=False):
        self.picks = list(methods)
        self.codes = list(codes)
        self.offered = []
        self.events = []
        self.otp_calls = 0
        self.switch_polls = 0
        self.switch_after = switch_after
        self._retry = retry
        self.cancel = False

    def choose(self, methods):
        self.offered.append(list(methods))
        return self.picks.pop(0)

    def otp(self, attempt):
        self.otp_calls += 1
        assert attempt == self.otp_calls
        return self.codes.pop(0)

    def on_push(self, event):
        self.events.append(event)

    def should_switch(self):
        self.switch_polls += 1
        return self.switch_after is not None and self.switch_polls > self.switch_after

    def cancelled(self):
        return self.cancel

    def retry(self, error):
        return self._retry


def run(prompt, password=PASSWORD, **kw):
    return entrance.login(AUTHORIZE, "u@school.ch", password, cookies=None, mfa=prompt, **kw)


PUSH_OK = [{"Success": True, "Entropy": 42, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"}]
PENDING = {"Success": False, "Retry": True, "ResultValue": "AuthenticationPending"}
APPROVED = {"Success": True, "Ctx": "c2", "FlowToken": "f2"}
DENIED = {"Success": False, "Retry": False, "ResultValue": "PhoneAppDenied"}
OTP_BEGIN = {"Success": True, "SessionId": "S", "Ctx": "c1", "FlowToken": "f1"}
OTP_GOOD = {"Success": True, "ResultValue": "Success", "Ctx": "c2", "FlowToken": "f2"}
OTP_BAD = {"Success": False, "ResultValue": "OathCodeIncorrect", "Ctx": "c1", "FlowToken": "f1"}
BOTH = ("PhoneAppNotification", "PhoneAppOTP")


def test_no_mfa_completes_without_asking(monkeypatch):
    session(monkeypatch)
    p = Prompt()
    assert run(p)["code"] == "THECODE"
    assert p.offered == [] and p.events == []


def test_push_approved(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK, end=[PENDING, APPROVED])
    p = Prompt(methods=["push"])
    assert run(p)["code"] == "THECODE"
    assert p.offered == [["push", "otp"]]
    assert [e.state for e in p.events] == ["number_matching", "pending", "approved"]
    assert p.events[0].number == "42"
    assert FakeSession.last.sent("ProcessAuth")[0]["mfaAuthMethod"] == "PhoneAppNotification"


def test_only_offered_methods_are_listed(monkeypatch):
    mfa_session(monkeypatch, "PhoneAppOTP", "OneWaySMS", begin=[OTP_BEGIN], end=[OTP_GOOD])
    p = Prompt(methods=["otp"])
    run(p)
    assert p.offered == [["otp"]]


def test_push_denied_raises(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK, end=[DENIED])
    with pytest.raises(entrance.PushError) as e:
        run(Prompt())
    assert e.value.state == "denied"


def test_push_denied_then_retry_with_code(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK + [OTP_BEGIN], end=[DENIED, OTP_GOOD])
    p = Prompt(methods=["push", "otp"], retry=True)
    assert run(p)["code"] == "THECODE"
    assert len(p.offered) == 2


def test_push_timeout(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK)
    with pytest.raises(entrance.PushError) as e:
        run(Prompt(), push_timeout=0)
    assert e.value.state == "timed_out"


def test_otp_ok(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=[OTP_BEGIN], end=[OTP_GOOD])
    p = Prompt(methods=["otp"], codes=["654321"])
    assert run(p)["code"] == "THECODE"
    assert FakeSession.last.sent("EndAuth")[0]["AdditionalAuthData"] == "654321"
    assert FakeSession.last.sent("ProcessAuth")[0]["otc"] == "654321"


def test_otp_wrong_then_ok(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=[OTP_BEGIN], end=[OTP_BAD, OTP_GOOD])
    p = Prompt(methods=["otp"], codes=["111111", "222222"])
    run(p)
    assert p.otp_calls == 2
    assert FakeSession.last.sent("ProcessAuth")[0]["otc"] == "222222"


def test_otp_attempts_exhausted(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=[OTP_BEGIN], end=[OTP_BAD] * 3)
    p = Prompt(methods=["otp"], codes=["1", "2", "3"])
    with pytest.raises(entrance.OtpRejected) as e:
        run(p)
    assert e.value.attempts == 3 and p.otp_calls == 3
    assert isinstance(e.value, entrance.MfaRequired)


def test_switch_push_to_otp(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK + [OTP_BEGIN], end=[PENDING, OTP_GOOD])
    p = Prompt(methods=["push", "otp"], codes=["123456"], switch_after=1)
    assert run(p)["code"] == "THECODE"
    assert [e.state for e in p.events] == ["number_matching", "pending"]
    assert p.offered == [["push", "otp"], ["push", "otp"]]


def test_switch_otp_to_push(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=[OTP_BEGIN] + PUSH_OK, end=[APPROVED])

    class P(Prompt):
        def otp(self, attempt):
            raise MfaSwitch()

    p = P(methods=["otp", "push"])
    assert run(p)["code"] == "THECODE"
    assert p.events[-1].state == "approved"


def test_cancel_during_push(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK)
    p = Prompt()
    p.cancel = True
    with pytest.raises(MfaCancelled):
        run(p)


def test_wrong_password(monkeypatch):
    session(monkeypatch, creds_page(sErrorCode="50126", strServiceExceptionMessage="bad"))
    with pytest.raises(entrance.InvalidCredentials):
        run(Prompt())


def test_unknown_account_is_invalid_credentials(monkeypatch):
    session(monkeypatch, gct={"IfExistsResult": 1})
    with pytest.raises(entrance.InvalidCredentials):
        run(Prompt())


def test_federated_account(monkeypatch):
    fed = "https://adfs.school.ch/adfs/ls"
    session(monkeypatch, gct={"Credentials": {"FederationRedirectUrl": fed}})
    with pytest.raises(entrance.Unsupported) as e:
        run(Prompt())
    assert isinstance(e.value, entrance.FederatedAccount)
    assert e.value.redirect_url == fed
    assert isinstance(e.value, entrance.LoginFailed)


def test_adfs_redirect_after_password(monkeypatch):
    session(monkeypatch, redirect("https://adfs.school.ch/adfs/ls/?wa=wsignin1.0"))
    with pytest.raises(entrance.FederatedAccount):
        run(Prompt())


def test_no_usable_mfa_method(monkeypatch):
    mfa_session(monkeypatch, "OneWaySMS", "TwoWayVoiceMobile")
    with pytest.raises(entrance.UnsupportedMfa) as e:
        run(Prompt())
    assert e.value.offered == ["OneWaySMS", "TwoWayVoiceMobile"]
    assert isinstance(e.value, entrance.MfaRequired) and isinstance(e.value, entrance.Unsupported)


def test_conditional_access_block_page(monkeypatch):
    session(monkeypatch, page(sErrorCode="53003", strServiceExceptionMessage="blocked"))
    with pytest.raises(entrance.Blocked) as e:
        run(Prompt())
    assert e.value.code == "53003"


def test_conditional_access_block_redirect(monkeypatch):
    loc = "https://cb.example/cb?error=access_denied&error_description=AADSTS53003%3A+Blocked"
    session(monkeypatch, redirect(loc))
    with pytest.raises(entrance.Blocked):
        run(Prompt())


def test_mfa_conflicts_with_push():
    with pytest.raises(ValueError):
        entrance.login(AUTHORIZE, "u", "p", push=True, mfa=Prompt())


def test_foci_and_push_login_pass_mfa(monkeypatch):
    import entrance._foci as foci

    seen = {}
    monkeypatch.setattr(_client, "login", lambda *a, **k: seen.update(k) or {"code": None})
    p = Prompt()
    with pytest.raises(entrance.TokenError):
        foci.foci_login("u", "pw", mfa=p, frt_store=None, cookies=None)
    assert seen["mfa"] is p and seen["password"] == "pw"
    with pytest.raises(entrance.TokenError):
        entrance.push_login("u", "pw", mfa=p)
    assert seen["mfa"] is p and seen["push"] is False


# --- password handling -------------------------------------------------------
def _everything(exc):
    return str(exc) + repr(exc) + "".join(traceback.format_exception(exc))


@pytest.mark.parametrize(
    "scenario", ["wrong", "denied", "otp_exhausted", "federated", "blocked", "ok"]
)
def test_password_never_leaks(monkeypatch, caplog, tmp_path, scenario):
    if scenario == "wrong":
        session(monkeypatch, creds_page(sErrorCode="50126"))
    elif scenario == "denied":
        mfa_session(monkeypatch, *BOTH, begin=PUSH_OK, end=[DENIED])
    elif scenario == "otp_exhausted":
        mfa_session(monkeypatch, *BOTH, begin=[OTP_BEGIN], end=[OTP_BAD] * 3)
    elif scenario == "federated":
        session(monkeypatch, redirect("https://adfs.school.ch/adfs/ls/"))
    elif scenario == "blocked":
        session(monkeypatch, page(sErrorCode="53003"))
    else:
        mfa_session(monkeypatch, *BOTH, begin=PUSH_OK, end=[APPROVED])
    p = Prompt(methods=["otp"] if scenario == "otp_exhausted" else ["push"], codes=["1", "2", "3"])
    dump = tmp_path / "dump.json"
    secret = Secret(PASSWORD)
    caplog.set_level(logging.DEBUG)
    try:
        run(p, password=secret, debug_dump=str(dump))
    except Exception as e:  # noqa: BLE001
        assert PASSWORD not in _everything(e)
    assert PASSWORD not in caplog.text
    assert PASSWORD not in repr(secret) and PASSWORD not in repr(p.__dict__)
    if scenario in ("wrong", "denied", "otp_exhausted", "ok"):
        assert not secret  # dropped once submitted
    if dump.exists():
        assert PASSWORD not in dump.read_text()


def test_secret_is_one_shot_and_unpicklable():
    import pickle

    s = Secret("x")
    assert s.take() == "x" and s.take() is None and not s
    with pytest.raises(TypeError):
        pickle.dumps(Secret("x"))


def test_password_sent_once_as_form_field(monkeypatch):
    mfa_session(monkeypatch, *BOTH, begin=PUSH_OK, end=[APPROVED])
    run(Prompt())
    sent = [p for m, u, p in FakeSession.last.calls if isinstance(p, dict) and "passwd" in p]
    assert len(sent) == 1 and sent[0]["passwd"] == PASSWORD


def test_legacy_params_unchanged():
    import inspect

    params = inspect.signature(entrance.login).parameters
    assert params["mfa"].default is None
    assert params["push"].default is False and params["totp_secret"].default is None
