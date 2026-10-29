"""Microsoft Authenticator **number-matching push** sign-in.

After the password is accepted, Microsoft sends a push notification to the
Authenticator app and shows a two-digit number on the sign-in surface; the user
taps that number in the app to approve. This module captures the number
*server-side* and streams it out as an event, so a caller (e.g. Schuly's
in-browser "link your Microsoft account" screen) can render "Open Authenticator
and tap 42" on its own UI instead of a Microsoft page.

The number lives in the internal Entra MFA flow Entrance already drives for
TOTP: the `SAS/BeginAuth` response for `AuthMethodId=PhoneAppNotification`
carries an `Entropy` integer - the number to tap - after which `SAS/EndAuth` is
polled (`PollCount` incrementing) until the user approves (`Success`), denies
(`Retry=false`), or the challenge times out. It is *not* exposed by the OAuth
device-code flow (that only ever returns the device `user_code`); see
docs/push.md.

Public surface: `push_login()` (returns a `Broker`), the `PushEvent` emitted to
`on_event`, the state constants, and `PushError`.
"""

import time
from dataclasses import dataclass

# Progress states carried by PushEvent.state.
NUMBER_MATCHING = "number_matching"  # the number to tap is now known
PENDING = "pending"  # waiting for the user to approve in the app
APPROVED = "approved"  # the user approved
DENIED = "denied"  # the user rejected the prompt
TIMED_OUT = "timed_out"  # no response before the deadline

# Authenticator push. Distinct from PhoneAppOTP (the TOTP method _client handles).
PUSH_METHOD = "PhoneAppNotification"


class PushError(RuntimeError):
    """A push challenge could not be started or was not approved. `state` is the
    terminal `PushEvent` state (`denied` / `timed_out`) when one applies."""

    def __init__(self, message, state=None):
        self.state = state
        super().__init__(message)


@dataclass
class PushEvent:
    """A progress update from a number-matching push sign-in.

    * `state` - one of the module's state constants.
    * `number` - the two-digit number to tap (set on `NUMBER_MATCHING`).
    * `message` - a human-readable line safe to show a user.
    * `expires_in` - seconds the challenge stays answerable (on `NUMBER_MATCHING`).
    """

    state: str
    number: str = None  # type: ignore[assignment]
    message: str = None  # type: ignore[assignment]
    expires_in: int = None  # type: ignore[assignment]


@dataclass
class _PushRequest:
    """How `_client` should run the push challenge when it reaches the MFA step."""

    on_event: object = None  # callable(PushEvent) | None
    timeout: float = 120
    interval: float = 3


def _emit(on_event, event):
    if on_event is not None:
        on_event(event)


def _format_number(entropy):
    """The number to tap, as a string, or None when the challenge carries none.

    `Entropy` is an int (e.g. 42); a missing value or 0 means no number-matching
    prompt (older tenants / a plain approve), in which case the user just
    approves in the app."""
    if isinstance(entropy, bool) or not isinstance(entropy, int) or entropy == 0:
        return None
    return f"{entropy:02d}"


def run_push_challenge(c, cfg, chosen, hdr, req):
    """Drive `BeginAuth` -> poll `EndAuth` for a push method, emitting events.

    Reuses the already-authenticated curl_cffi session `c` and the `$Config`
    (`cfg`) from the MFA page that `_client` parsed. Emits a `NUMBER_MATCHING`
    event with the tap number, a `PENDING` event per poll, and a terminal
    `APPROVED` event. Returns `(ctx, flow_token)` for the final ProcessAuth POST.
    Raises `PushError` (with `state`) on denial or timeout.
    """
    from ._client import _abs  # local: avoid a _client <-> _push import cycle

    begin_url, end_url = _abs(cfg["urlBeginAuth"]), _abs(cfg["urlEndAuth"])
    ctx, ft = cfg["sCtx"], cfg["sFT"]

    begin = c.post(
        begin_url,
        json={"AuthMethodId": chosen, "Method": "BeginAuth", "ctx": ctx, "flowToken": ft},
        headers=hdr,
    ).json()
    if not begin.get("Success"):
        raise PushError(f"BeginAuth failed: {begin.get('Message') or begin}")
    ctx = begin.get("Ctx", ctx)
    ft = begin.get("FlowToken", ft)
    session_id = begin.get("SessionId")
    number = _format_number(begin.get("Entropy"))

    timeout = req.timeout
    message = (
        f"Open Microsoft Authenticator and tap {number} to approve."
        if number
        else "Approve the sign-in request in Microsoft Authenticator."
    )
    _emit(
        req.on_event,
        PushEvent(NUMBER_MATCHING, number=number, message=message, expires_in=int(timeout)),
    )

    deadline = time.time() + timeout
    poll = 0
    while time.time() < deadline:
        poll += 1
        end = c.post(
            end_url,
            json={
                "AuthMethodId": chosen,
                "Method": "EndAuth",
                "ctx": ctx,
                "flowToken": ft,
                "SessionId": session_id,
                "PollCount": poll,
            },
            headers=hdr,
        ).json()
        if end.get("ErrCode"):
            raise PushError(f"EndAuth error {end['ErrCode']}: {end.get('Message') or end}")
        ctx = end.get("Ctx", ctx)
        ft = end.get("FlowToken", ft)
        if end.get("Success"):
            _emit(req.on_event, PushEvent(APPROVED, message="Approved."))
            return ctx, ft
        if not end.get("Retry", False):
            result = end.get("ResultValue") or "denied"
            _emit(req.on_event, PushEvent(DENIED, message=str(result)))
            raise PushError(f"Push rejected: {result}", state=DENIED)
        _emit(req.on_event, PushEvent(PENDING, message=end.get("ResultValue") or "waiting"))
        time.sleep(req.interval)

    _emit(req.on_event, PushEvent(TIMED_OUT, message="No response before the challenge expired."))
    raise PushError("Push approval timed out", state=TIMED_OUT)


def push_login(
    username,
    password,
    *,
    on_event=None,
    client_id=None,
    tenant="common",
    scope=None,
    cookies=None,
    frt_store=None,
    timeout=120,
    interval=3,
    **login_kwargs,
):
    """Sign in with Microsoft Authenticator number-matching push, return a `Broker`.

    Drives the headless credential sign-in (`username` + `password`); when
    Microsoft requires the second factor it triggers a push and streams progress
    to `on_event(PushEvent)` - a `number_matching` event carrying the two-digit
    number to tap, then `pending` per poll, then a terminal `approved` (after
    which this returns the `Broker`). On rejection or no response it raises
    `PushError` (its `state` is `denied` or `timed_out`).

    `client_id` defaults to OfficeHome (a pre-consented FOCI client); `scope`
    defaults to Graph `.default` + `offline_access`. `cookies` / `frt_store`
    default to None (nothing persisted), which suits a stateless web relay; pass
    paths to reuse a session or save the refresh token. The account must have
    Authenticator push enabled (the usual Microsoft default); an account with
    only TOTP raises `MfaRequired`. Extra kwargs pass through to `foci_login` /
    `entrance.login`.
    """
    from ._foci import _SCOPES, OFFICEHOME, foci_login

    return foci_login(
        username,
        password,
        client_id=client_id or OFFICEHOME,
        tenant=tenant,
        scope=scope or _SCOPES,
        cookies=cookies,
        frt_store=frt_store,
        push=True,
        on_push=on_event,
        push_timeout=timeout,
        push_interval=interval,
        **login_kwargs,
    )
