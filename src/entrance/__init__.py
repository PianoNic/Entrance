"""Entrance - browser-grade OAuth login for Microsoft-federated providers, no browser
(and, when headless can't finish, in your own browser)."""

from ._browser import browser_login, is_loopback
from ._client import (
    BROWSER_HEADERS,
    Blocked,
    FederatedAccount,
    InvalidCredentials,
    LoginFailed,
    MfaRequired,
    NeedsCredentials,
    OtpRejected,
    Unsupported,
    UnsupportedMfa,
    login,
    parse_config,
)
from ._device import DeviceCodeError, device_login
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
from ._http import client as http_client
from ._http import warm_up
from ._mfa import OTP, OTP_ATTEMPTS, PUSH, MfaCancelled, MfaPrompt, MfaSwitch, Secret
from ._push import (
    APPROVED,
    DENIED,
    NUMBER_MATCHING,
    PENDING,
    TIMED_OUT,
    PushError,
    PushEvent,
    push_login,
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
    "device_login",
    "DeviceCodeError",
    "push_login",
    "PushEvent",
    "PushError",
    "NUMBER_MATCHING",
    "PENDING",
    "APPROVED",
    "DENIED",
    "TIMED_OUT",
    "Broker",
    "http_client",
    "warm_up",
    "TokenError",
    "read_secret",
    "write_secret",
    "GRAPH_SCOPE",
    "OFFICEHOME",
    "BROWSER_HEADERS",
    "MfaRequired",
    "LoginFailed",
    "NeedsCredentials",
    "MfaPrompt",
    "MfaSwitch",
    "MfaCancelled",
    "Secret",
    "PUSH",
    "OTP",
    "OTP_ATTEMPTS",
    "InvalidCredentials",
    "Unsupported",
    "FederatedAccount",
    "UnsupportedMfa",
    "Blocked",
    "OtpRejected",
]
