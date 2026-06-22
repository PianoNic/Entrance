"""Entrance - browser-grade OAuth login for Microsoft-federated providers, no browser."""

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
    "parse_config",
    "BROWSER_HEADERS",
    "MfaRequired",
    "LoginFailed",
    "NeedsCredentials",
]
