"""Smoke tests: the public surface imports and is shaped as expected."""

import inspect

import entrance
from entrance import _client


def test_login_is_callable():
    assert callable(entrance.login)


def test_exceptions_exist():
    assert issubclass(entrance.MfaRequired, Exception)
    assert issubclass(entrance.LoginFailed, Exception)
    assert issubclass(entrance.NeedsCredentials, Exception)


def test_browser_headers_impersonate_opera():
    # The whole trick: present as Opera (a non-Chrome Chromium) so Entra skips
    # the JS-only Chrome-SSO page. Guard against a regression on the UA.
    ua = entrance.BROWSER_HEADERS["User-Agent"]
    assert "OPR/" in ua
    assert "Opera" in entrance.BROWSER_HEADERS["sec-ch-ua"]


def test_parse_config_extracts_sft():
    html = '<script>$Config={"a":1,"sFT":"tok","x":{"y":2}};//]]></script>'
    cfg = entrance.parse_config(html)
    assert cfg["sFT"] == "tok"


def test_login_accepts_totp_code_and_secret():
    params = inspect.signature(entrance.login).parameters
    assert "totp_secret" in params
    assert "totp_code" in params


def test_otp_source_code_used_as_is_and_wins_over_secret():
    assert _client._make_otp_source(None, "123456")() == "123456"
    assert _client._make_otp_source("JBSWY3DPEHPK3PXP", 654321)() == "654321"  # code wins


def test_otp_source_generates_from_secret():
    code = _client._make_otp_source("JBSWY3DPEHPK3PXP", None)()
    assert code.isdigit() and len(code) == 6


def test_otp_source_none_when_nothing_given():
    assert _client._make_otp_source(None, None) is None
