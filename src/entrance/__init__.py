"""Entrance - browser-grade OAuth login for Microsoft-federated providers, no browser
(and, when headless can't finish, in your own browser)."""

from ._browser import browser_login, is_loopback
from ._client import (
    BROWSER_HEADERS,
    LoginFailed,
    MfaRequired,
    NeedsCredentials,
    login,
    parse_config,
)
from ._enroll import EnrollmentError, enroll_totp
from ._foci import (
    GRAPH_SCOPE,
    OFFICEHOME,
    Broker,
    TokenError,
    foci_login,
    read_secret,
    write_secret,
)
from ._totp import TotpDevice, new_totp, totp_now, totp_verify

__all__ = [
    "login",
    "browser_login",
    "is_loopback",
    "parse_config",
    "new_totp",
    "totp_now",
    "totp_verify",
    "TotpDevice",
    "enroll_totp",
    "EnrollmentError",
    "foci_login",
    "Broker",
    "TokenError",
    "read_secret",
    "write_secret",
    "GRAPH_SCOPE",
    "OFFICEHOME",
    "BROWSER_HEADERS",
    "MfaRequired",
    "LoginFailed",
    "NeedsCredentials",
]
