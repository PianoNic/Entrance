"""OAuth 2.0 device authorization grant ("device code flow").

The cleanest interactive sign-in for a CLI: no redirect URI, no loopback server,
no copy-pasting a callback URL. The library shows a short code and a URL; the
user opens the URL (a normal Microsoft sign-in page, so push / number-matching /
passkeys all work), enters the code, and the library polls until the tokens
come back - then wraps them in a `Broker`.

The sign-in client must have the device flow enabled; Microsoft's `OfficeHome`
client does not, but the `Office` client (`d3590ed6-...`) does and yields a FOCI
family token, so it's the usual choice for reaching Microsoft 365.
"""

import sys
import time
import webbrowser

from ._foci import _TOKEN, GRAPH_SCOPE, Broker, _post_token, write_secret

_DEVICECODE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
_FATAL = {"authorization_declined", "expired_token", "access_denied", "bad_verification_code"}


class DeviceCodeError(RuntimeError):
    """The device code flow failed (declined, expired, or the client can't use it)."""

    def __init__(self, error, description=""):
        self.error = error
        super().__init__(f"{error}: {description}" if description else str(error))


def _default_prompt(message, **_):
    print(message, file=sys.stderr, flush=True)


def device_login(
    client_id,
    *,
    tenant="common",
    scope=None,
    frt_store=None,
    on_prompt=None,
    open_browser=False,
    timeout=900,
):
    """Sign in with the device code flow and return a `Broker`.

    Shows the user a short code and a URL (`on_prompt(verification_uri=,
    user_code=, message=)`, defaulting to a stderr print), optionally opens the
    URL in a browser, then polls until they finish. `scope` defaults to Graph
    `.default` + `offline_access`. With `frt_store`, the refresh token is saved
    (atomically, 0600) for password-free reruns. `client_id` must be a
    device-flow-enabled client.
    """
    scope = scope or f"{GRAPH_SCOPE} offline_access"
    init = _post_token(_DEVICECODE.format(tenant=tenant), {"client_id": client_id, "scope": scope})
    if not init.get("device_code"):
        raise DeviceCodeError(
            init.get("error", "no_device_code"),
            init.get("error_description") or "client may not support the device flow",
        )

    verification_uri = init.get("verification_uri") or init.get("verification_url")
    user_code = init["user_code"]
    message = init.get("message") or (
        f"To sign in, open {verification_uri} and enter the code {user_code}"
    )
    (on_prompt or _default_prompt)(
        verification_uri=verification_uri, user_code=user_code, message=message
    )
    if open_browser and verification_uri:
        try:
            webbrowser.open(verification_uri)
        except Exception:  # noqa: BLE001 - the printed code is the fallback
            pass

    interval = init.get("interval", 5)
    deadline = time.time() + min(timeout, init.get("expires_in", 900))
    token_url = _TOKEN.format(tenant=tenant)
    while time.time() < deadline:
        time.sleep(interval)
        r = _post_token(
            token_url,
            {
                "grant_type": _DEVICE_GRANT,
                "client_id": client_id,
                "device_code": init["device_code"],
            },
        )
        if r.get("access_token"):
            frt = r.get("refresh_token")
            if not frt:
                raise DeviceCodeError("no_refresh_token", "no refresh token in the response")
            if frt_store:
                write_secret(frt_store, frt)
            return Broker(frt, tenant, store=frt_store)
        error = r.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise DeviceCodeError(error or "device_error", r.get("error_description") or "")
    raise DeviceCodeError("expired_token", "the code expired before sign-in completed")
