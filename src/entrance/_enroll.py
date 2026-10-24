"""Enroll a brand-new software-TOTP ("authenticator app") method on the
signed-in user's OWN account, headlessly, and return its Base32 secret.

This drives the same **My Sign-Ins / Security info** backend the portal uses
when you pick *Add → Authenticator app → "use a different app"*:

    POST /api/session/authorize                       -> a session context
    POST /api/authenticationmethods/initializemobileapp {securityInfoType:3}
                                                       -> the TOTP SecretKey
    POST /api/authenticationmethods/new   {Type:3, Data:{secretKey}}
                                                       -> a VerificationContext
    POST /api/authenticationmethods/verify {Type:3, VerificationContext,
                                            VerificationData:<code>}  -> active

The one hard requirement is a **fresh strong MFA** (Entra's `ngcmfa` claim):
Microsoft won't let you add a second factor without proving a current one. So
you must already hold a working factor - pass an existing `totp_secret` /
`totp_code`, or `interactive=True` to approve it in a browser. This **mutates
the account** (it adds a sign-in method); it never touches existing methods.
"""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

from curl_cffi import requests

from ._client import BROWSER_HEADERS, IMPERSONATE
from ._totp import TotpDevice


def _pkce():
    """A PKCE (verifier, S256 challenge) pair."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


PORTAL_CLIENT = "19db86c3-b2b9-44cc-b339-36da233a3be2"  # "My Sign-Ins"
PORTAL_REDIRECT = "https://mysignins.microsoft.com"
_API = "https://mysignins.microsoft.com/api"
_AUTHORIZE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_SOFTWARE_OATH = 3  # securityInfoType / Type for a software-OATH (TOTP) method
# Force a fresh strong MFA on the sign-in - the Security info API demands ngcmfa.
_NGCMFA_CLAIMS = json.dumps(
    {
        "id_token": {"amr": {"essential": True, "values": ["mfa", "ngcmfa"]}},
        "access_token": {"amr": {"essential": True, "values": ["mfa", "ngcmfa"]}},
    },
    separators=(",", ":"),
)


class EnrollmentError(RuntimeError):
    """The Security info API refused a step (e.g. no fresh MFA, or a bad code)."""


def _portal_token(username, password, totp_secret, totp_code, tenant, cookies, interactive):
    """A fresh access token for the My Sign-Ins client, carrying ngcmfa."""
    from ._client import login  # local import keeps the module graph acyclic

    verifier, challenge = _pkce()
    authorize_url = (
        _AUTHORIZE.format(tenant=tenant)
        + "?"
        + urlencode(
            {
                "client_id": PORTAL_CLIENT,
                "response_type": "code",
                "redirect_uri": PORTAL_REDIRECT,
                "response_mode": "query",
                "scope": "openid profile email",
                "state": secrets.token_urlsafe(12),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "claims": _NGCMFA_CLAIMS,
                **({"login_hint": username} if username else {}),
            }
        )
    )
    res = login(
        authorize_url,
        username=username,
        password=password,
        totp_secret=totp_secret,
        totp_code=totp_code,
        code_verifier=verifier,
        client_id=PORTAL_CLIENT,
        redirect_uri=PORTAL_REDIRECT,
        cookies=cookies,
        interactive=interactive,
    )
    code = res.get("code")
    if not code:
        raise EnrollmentError(
            "My Sign-Ins sign-in returned no authorization code "
            f"(got keys: {', '.join(k for k, v in res.items() if v)})."
        )
    # My Sign-Ins is a Single-Page-Application client: its token endpoint only
    # redeems a code on a cross-origin request, so the exchange must carry an
    # Origin matching the registered SPA redirect (else AADSTS9002327).
    token = _exchange_spa(code, verifier, tenant)
    if not token:
        raise EnrollmentError("Token exchange returned no access token for My Sign-Ins.")
    return token


def _exchange_spa(code, verifier, tenant):
    """Redeem `code` for the My Sign-Ins access token - as a cross-origin (SPA)
    request, which the client requires."""
    c = requests.Session(impersonate=IMPERSONATE)
    c.headers.update(BROWSER_HEADERS)
    r = c.post(
        _TOKEN.format(tenant=tenant),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": PORTAL_CLIENT,
            "code_verifier": verifier,
            "redirect_uri": PORTAL_REDIRECT,
            # the /api backend validates aud == the portal app, so ask for the
            # app's own token (.default), not a Graph token
            "scope": f"{PORTAL_CLIENT}/.default",
        },
        headers={"Origin": PORTAL_REDIRECT, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        data = r.json()
    except ValueError:
        raise EnrollmentError(
            f"Token endpoint non-JSON ({r.status_code}): {r.text[:200]}"
        ) from None
    if not data.get("access_token"):
        raise EnrollmentError(
            f"Token exchange failed: {data.get('error_description') or data.get('error') or data}"
        )
    return data["access_token"]


class _Api:
    """The My Sign-Ins Security-info backend, as the signed-in user."""

    def __init__(self, token):
        self._c = requests.Session(impersonate=IMPERSONATE)
        self._c.headers.update(BROWSER_HEADERS)
        self._c.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "ajaxrequest": "true",  # the backend requires this AJAX marker
                "Accept": "application/json",
            }
        )

    def post(self, path, body=None):
        r = self._c.post(f"{_API}/{path}", data=json.dumps(body) if body is not None else b"")
        try:
            data = r.json()
        except ValueError:
            raise EnrollmentError(f"{path}: non-JSON ({r.status_code}): {r.text[:200]}") from None
        if r.status_code >= 400:
            raise EnrollmentError(f"{path}: HTTP {r.status_code}: {str(data)[:200]}")
        if isinstance(data, dict) and data.get("ErrorCode", 0):
            raise EnrollmentError(
                f"{path}: ErrorCode {data['ErrorCode']} ({data.get('ErrorType')})"
            )
        return data

    def set_session(self, ctx):
        self._c.headers["sessionctxv2"] = ctx


def enroll_totp(
    username=None,
    password=None,
    *,
    totp_secret=None,
    totp_code=None,
    tenant="common",
    account_name=None,
    cookies=".ms_session.json",
    interactive=False,
):
    """Register a new software-TOTP method on the signed-in user's own account
    and return it as a `TotpDevice` - its `.secret` then feeds
    `login(totp_secret=...)` for fully headless MFA from here on.

    Authenticates fresh (to get the `ngcmfa` claim Entra requires for managing
    sign-in methods), so pass a working second factor: `totp_secret` /
    `totp_code`, or `interactive=True` to approve it in a browser.

    **Mutates the account**: it adds a sign-in method (existing methods are left
    untouched). Use only on accounts you own / are authorized to change.
    """
    token = _portal_token(username, password, totp_secret, totp_code, tenant, cookies, interactive)
    api = _Api(token)

    session = api.post("session/authorize")
    ctx = session.get("sessionCtxV2")
    if not ctx:
        raise EnrollmentError(f"session/authorize gave no session context: {str(session)[:200]}")
    if session.get("isAuthorized") is False:
        raise EnrollmentError("session/authorize: not authorized for Security info.")
    api.set_session(ctx)

    init = api.post(
        "authenticationmethods/initializemobileapp", {"securityInfoType": _SOFTWARE_OATH}
    )
    secret = init.get("SecretKey")
    if not secret:
        raise EnrollmentError(f"initializemobileapp returned no SecretKey: {str(init)[:200]}")
    account = account_name or init.get("AccountName") or (username or "")

    new = api.post(
        "authenticationmethods/new",
        {
            "Type": _SOFTWARE_OATH,
            # Data is a JSON *string*, as the portal sends it.
            "Data": json.dumps(
                {
                    "secretKey": secret,
                    "affinityRegion": None,
                    "isResendNotificationChallenge": False,
                }
            ),
        },
    )
    vctx = new.get("VerificationContext")
    if not vctx:
        raise EnrollmentError(f"authenticationmethods/new gave no VerificationContext: {new}")

    device = TotpDevice(secret=secret, account_name=account)
    # Confirm with a live code; wait for a fresh window so it stays valid.
    if time.time() % device.period > device.period - 3:
        time.sleep(3)
    verify = api.post(
        "authenticationmethods/verify",
        {"Type": _SOFTWARE_OATH, "VerificationContext": vctx, "VerificationData": device.now()},
    )
    if verify.get("VerificationState") != 2:
        raise EnrollmentError(f"verify did not activate the method: {str(verify)[:200]}")
    return device
