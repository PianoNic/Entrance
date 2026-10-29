"""FOCI token broker: sign in once against a pre-consented Microsoft
first-party client, get a **family refresh token** (FOCI), then trade it for an
access token for whichever first-party client a call needs - no app
registration, no further sign-ins. The refresh token is persisted atomically
(0600) so later runs skip the sign-in entirely.

This is the generic Microsoft side of the flow; a caller (e.g. a Graph client)
supplies which client ids / scopes to broker.
"""

import base64
import hashlib
import logging
import os
import secrets
import tempfile
import time
from urllib.parse import urlencode

import httpx

from . import _http as http

log = logging.getLogger("entrance.foci")

_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_AUTHORIZE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# OfficeHome is pre-consented and issues a FOCI (family=1) refresh token that
# the broker trades for the other family clients' tokens - a good default
# sign-in client for reaching Microsoft Graph without registering an app.
OFFICEHOME = "4765445b-32c6-49b0-83e6-1d93765276ca"
# Native-client redirect: redeems server-side (no SPA/Origin dance). entrance
# intercepts the code here; it is never actually delivered.
_REDIRECT = "https://login.microsoftonline.com/common/oauth2/nativeclient"
_SCOPES = "https://graph.microsoft.com/.default offline_access openid profile"


class TokenError(RuntimeError):
    """The token endpoint refused a grant. `error` is the OAuth error code
    (e.g. `invalid_grant` for an expired or revoked refresh token)."""

    def __init__(self, error, description):
        self.error = error
        super().__init__(f"{error}: {description}")


def _post_token(url, data):
    t0 = time.perf_counter()
    try:
        r = http.client().post(url, data=data)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Token endpoint error: {e}") from None
    finally:
        log.debug("token POST %s took %.0f ms", url, (time.perf_counter() - t0) * 1000)
    try:
        return r.json()  # success or an AADSTS error body
    except ValueError:
        raise RuntimeError(f"Token endpoint error: HTTP {r.status_code}") from None


def read_secret(path):
    """The stripped contents of `path`, or None if it is missing/empty."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def write_secret(path, value):
    """Atomically write `value` to `path` with owner-only permissions: a temp
    file in the same directory is fully written, then `os.replace`d over the
    target, so a crash mid-write never truncates the stored token."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".entrance-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


class Broker:
    """Holds a FOCI family refresh token and mints/caches an access token per
    first-party client on demand. Callable as `broker(client_id) -> token`, or
    `broker(client_id, scope)` for a non-Graph resource.

    With `store`, the refresh token is written back (atomically, 0600) every
    time it rotates."""

    def __init__(self, refresh_token, tenant="common", store=None):
        self._frt = refresh_token
        self._url = _TOKEN.format(tenant=tenant)
        self._store = store
        self._cache = {}  # (client_id, scope) -> (access_token, expiry_epoch)

    @property
    def refresh_token(self):
        return self._frt

    def __call__(self, client_id, scope=GRAPH_SCOPE):
        tok, exp = self._cache.get((client_id, scope), (None, 0))
        if tok and exp - 60 > time.time():
            return tok
        r = _post_token(
            self._url,
            {
                "grant_type": "refresh_token",
                "refresh_token": self._frt,
                "client_id": client_id,
                "scope": scope,
            },
        )
        if not r.get("access_token"):
            raise TokenError(
                r.get("error", "no_token"),
                f"client {client_id}: {r.get('error_description') or r}",
            )
        new = r.get("refresh_token")
        if new and new != self._frt:  # FRT rotates on use
            self._frt = new
            if self._store:
                write_secret(self._store, new)
        self._cache[(client_id, scope)] = (
            r["access_token"],
            time.time() + r.get("expires_in", 3600),
        )
        return r["access_token"]


def _pkce():
    v = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    return v, c


def _broker_from_store(frt_store, tenant, probe_client):
    """A Broker built from the saved refresh token, or None if there is no
    usable one (missing, expired or revoked - a dead token is deleted)."""
    frt = read_secret(frt_store)
    if not frt:
        return None
    broker = Broker(frt, tenant, store=frt_store)
    try:
        broker(probe_client)  # prove the token is alive before skipping sign-in
    except TokenError as e:
        if e.error in ("invalid_grant", "interaction_required"):
            os.remove(frt_store)
            return None
        raise
    return broker


def foci_login(
    username=None,
    password=None,
    *,
    client_id=OFFICEHOME,
    tenant="common",
    scope=_SCOPES,
    redirect_uri=_REDIRECT,
    totp_secret=None,
    totp_code=None,
    cookies=".ms_session.json",
    frt_store=".ms_frt",
    probe_client=None,
    interactive=False,
    device=False,
    open_browser=False,
    on_prompt=None,
    **login_kwargs,
):
    """Sign in against a pre-consented first-party client and return a `Broker`
    on its FOCI family refresh token - no app registration.

    If `frt_store` holds a live refresh token no sign-in happens at all;
    otherwise the sign-in runs and the new token is saved there
    (`frt_store=None` disables persistence). Pick how to sign in:
      * default - headless `entrance.login` (password + TOTP, or seeded cookies).
      * `interactive=True` / `"always"` - finish in a browser.
      * `device=True` - the device code flow (show a short code, the user enters
        it at a URL): no redirect, no loopback, no copy-paste. The sign-in
        `client_id` must support it (Microsoft's Office client does; OfficeHome
        does not). `open_browser=True` opens the code URL; `on_prompt` overrides
        how the code is shown.
    `probe_client` is the client id used to validate a stored token (defaults to
    `client_id`). Extra kwargs pass through to `entrance.login`.
    """
    from ._client import login  # local import keeps the module graph acyclic

    if frt_store:
        broker = _broker_from_store(frt_store, tenant, probe_client or client_id)
        if broker:
            return broker

    if device:
        from ._device import device_login

        return device_login(
            client_id,
            tenant=tenant,
            scope=scope,
            frt_store=frt_store,
            on_prompt=on_prompt,
            open_browser=open_browser,
        )

    verifier, challenge = _pkce()
    authorize_url = (
        _AUTHORIZE.format(tenant=tenant)
        + "?"
        + urlencode(
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "response_mode": "query",
                "scope": scope,
                "state": secrets.token_urlsafe(16),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
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
        redirect_uri=redirect_uri,
        cookies=cookies,
        interactive=interactive,
        **login_kwargs,
    )
    if not res.get("code"):
        raise TokenError("no_code", "No authorization code intercepted; keys: " + ", ".join(res))

    tokens = _post_token(
        _TOKEN.format(tenant=tenant),
        {
            "grant_type": "authorization_code",
            "code": res["code"],
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    frt = tokens.get("refresh_token")
    if not frt:
        raise TokenError(
            tokens.get("error", "no_refresh_token"),
            f"No refresh token from sign-in: {tokens.get('error_description') or tokens}",
        )
    if frt_store:
        write_secret(frt_store, frt)
    return Broker(frt, tenant, store=frt_store)
