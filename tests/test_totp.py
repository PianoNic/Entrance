"""Software TOTP helper: generation, provisioning URI, compute/verify.
Deterministic against a known secret; no network."""

from urllib.parse import parse_qs, unquote, urlsplit

import pyotp

import entrance

# RFC 6238-style fixed secret for deterministic assertions.
SECRET = "JBSWY3DPEHPK3PXP"


def test_new_totp_random_secret_is_valid_base32():
    d = entrance.new_totp("you@school.ch")
    assert len(d.secret) >= 16 and d.secret.isalnum() and d.secret.upper() == d.secret
    # usable immediately: its own code verifies
    assert d.verify(d.now())


def test_new_totp_accepts_custom_secret_and_normalizes():
    d = entrance.new_totp("you@school.ch", secret="jbsw y3dp ehpk 3pxp")
    assert d.secret == SECRET  # upper-cased, spaces stripped


def test_provisioning_uri_shape():
    d = entrance.new_totp("you@school.ch", issuer="Contoso", secret=SECRET)
    u = urlsplit(d.uri)
    assert u.scheme == "otpauth" and u.netloc == "totp"
    q = parse_qs(u.query)
    assert q["secret"] == [SECRET]
    assert q["issuer"] == ["Contoso"]
    assert "Contoso:you@school.ch" in unquote(u.path)


def test_now_matches_pyotp():
    d = entrance.new_totp("x", secret=SECRET)
    assert d.now() == pyotp.TOTP(SECRET).now()
    assert entrance.totp_now(SECRET) == pyotp.TOTP(SECRET).now()


def test_verify_window_and_rejects_wrong():
    d = entrance.new_totp("x", secret=SECRET)
    assert d.verify(d.now())
    assert d.verify(" " + d.now() + " ")  # whitespace tolerated
    assert not d.verify("000000") or pyotp.TOTP(SECRET).now() == "000000"
    assert entrance.totp_verify(SECRET, pyotp.TOTP(SECRET).now())


def test_as_dict_round_trips():
    d = entrance.new_totp("you@school.ch", secret=SECRET)
    data = d.as_dict()
    assert data["secret"] == SECRET and data["uri"] == d.uri
    assert set(data) == {"secret", "uri", "account_name", "issuer", "digits", "period"}


def test_feeds_login_totp_secret():
    # the whole point: the generated secret is what login(totp_secret=) expects
    d = entrance.new_totp("you@school.ch")
    src = entrance._client._make_otp_source(d.secret, None)
    assert d.verify(src())
