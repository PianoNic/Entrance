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

__all__ = [
    "login",
    "browser_login",
    "is_loopback",
    "parse_config",
    "BROWSER_HEADERS",
    "MfaRequired",
    "LoginFailed",
    "NeedsCredentials",
]
