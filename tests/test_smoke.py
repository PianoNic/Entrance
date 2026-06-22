"""Smoke tests: the public surface imports and is shaped as expected."""

import entrance


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
