"""
Headless login for any OAuth2 provider that federates to Microsoft Entra.

Give it an authorize URL - the kind your provider hands you to open in a
browser - and it drives the Microsoft sign-in over pure HTTP (no browser),
intercepts the authorization `code` at the callback, and optionally exchanges
it for tokens.

Knows nothing about any specific provider: client_id / redirect_uri / state are
read from the authorize URL; the token endpoint is whatever you pass in.
"""

import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from curl_cffi import requests

from ._mfa import OTP, OTP_ATTEMPTS, PUSH, MfaCancelled, MfaSwitch, Secret, hook
from ._push import PUSH_METHOD, PushError, _PushRequest, run_push_challenge

IMPERSONATE = "chrome"
# ponytail: ESTS serves a JS-only Chrome-SSO "pull" page (hpgid=6, no sFT) to
# *Google Chrome* (which supports the BSSO extension) but the plain credential
# page (hpgid=1104, has sFT) to other Chromium browsers. Impersonating Opera -
# a non-Chrome Chromium - skips the un-replayable SSO-pull step entirely.
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 OPR/132.0.0.0",
    "sec-ch-ua": '"Chromium";v="148", "Opera";v="132", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
}

_TOTP_METHODS = ("PhoneAppOTP",)  # authenticator-app OTP
_MFA_CODES = {"50074", "50076", "50079", "500121", "50072"}


class MfaRequired(RuntimeError):
    pass


class LoginFailed(RuntimeError):
    pass


class NeedsCredentials(RuntimeError):
    """Silent (cookie-jar) attempt didn't authenticate - fall back to password."""


class InvalidCredentials(LoginFailed):
    """Microsoft rejected the username or password (AADSTS50126 and friends)."""


class Unsupported(LoginFailed):
    """The account can't be signed in headlessly: federated to another IdP
    (ADFS/Okta/...), an expired password, or a second factor Entrance can't
    drive. Callers should fall back to a browser or device-code sign-in."""


class FederatedAccount(Unsupported):
    """The account's sign-in is federated to another identity provider.
    `redirect_url` is where Microsoft would send the user (may be None)."""

    def __init__(
        self, message="Account is federated to another identity provider", redirect_url=None
    ):
        self.redirect_url = redirect_url
        super().__init__(message)


class UnsupportedMfa(Unsupported, MfaRequired):
    """MFA is required but the account offers no method Entrance can drive (only
    SMS/voice/FIDO/...) or isn't enrolled. `offered` lists Microsoft's method ids."""

    def __init__(self, message, offered=()):
        self.offered = sorted(m for m in offered if m)
        super().__init__(message)


class Blocked(LoginFailed):
    """Microsoft refused the sign-in by policy: Conditional Access (AADSTS530xx),
    a compliant/managed device requirement, a locked or disabled account.
    `code` is the AADSTS number as a string."""

    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message)


class OtpRejected(MfaRequired):
    """Microsoft rejected every authenticator code that was tried (`attempts`)."""

    def __init__(self, message, attempts=0):
        self.attempts = attempts
        super().__init__(message)


_INVALID_CREDENTIAL_CODES = {"50126", "50034", "50056", "50064", "50144"}
_BLOCKED_CODES = {
    "50053", "50057", "50097", "50105", "50131", "50158", "53000", "53001", "53002",
    "53003", "53004", "530003", "530032", "530034", "53010", "70044",
}  # fmt: skip
_UNSUPPORTED_CODES = {"50055", "50133", "50173", "81016", "50011"}


def _aadsts(text):
    m = re.search(r"AADSTS(\d+)", str(text or ""))
    return m.group(1) if m else None


def _raise_entra_error(code, text, prefix="Entra error"):
    """Raise the most specific `LoginFailed` for a Microsoft error code/message.
    Only Microsoft's own error text is used - never anything the caller sent."""
    code = str(code or "") or _aadsts(text) or ""
    text = str(text or "").strip()[:300]
    if code in _INVALID_CREDENTIAL_CODES:
        raise InvalidCredentials("Wrong username or password")
    if code in _BLOCKED_CODES:
        raise Blocked(f"Sign-in blocked by policy (AADSTS{code})", code=code)
    if code in _UNSUPPORTED_CODES:
        raise Unsupported(f"Sign-in not supported here (AADSTS{code})")
    raise LoginFailed(f"{prefix} sErrorCode={code}: {text}" if code else f"{prefix}: {text}")


# --- helpers ----------------------------------------------------------------
def _iter_config_blobs(text):
    """Yield each $Config={...} JSON blob, brace-balanced, ignoring braces in strings."""
    for m in re.finditer(r"\$Config\s*=\s*\{", text):
        start = m.end() - 1
        depth, i, in_str, esc, quote = 0, start, False, False, ""
        while i < len(text):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == quote:
                    in_str = False
            elif c in "\"'":
                in_str, quote = True, c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield text[start : i + 1]
                    break
            i += 1


def parse_config(text):
    """Return the $Config carrying the flow token (sFT), else the first one."""
    fallback = None
    for blob in _iter_config_blobs(text):
        try:
            cfg = json.loads(blob)
        except ValueError:
            continue
        if "sFT" in cfg:
            return cfg
        fallback = fallback or cfg
    return fallback


def _is_redirect(r):
    return r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers


def _abs(url, base="https://login.microsoftonline.com"):
    return url if url.startswith("http") else urljoin(base + "/", url)


def _q(url):
    return dict(parse_qsl(urlsplit(url).query))


def _add_params(url, **extra):
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    q.update(extra)
    return urlunsplit(parts._replace(query=urlencode(q)))


# --- cookie handling: file path OR inline list, in and out ------------------
def _seed_cookies(c, cookies):
    """Seed the session from `cookies` (a file path str, or an inline list of
    cookie dicts). Returns True if anything was loaded."""
    if isinstance(cookies, str):
        if not os.path.exists(cookies):
            return False
        try:
            with open(cookies, encoding="utf-8") as f:
                data = json.load(f)
        except (ValueError, OSError):
            return False
    elif isinstance(cookies, (list, tuple)):
        data = cookies
    else:
        return False
    for ck in data or []:
        try:
            c.cookies.set(
                ck["name"], ck["value"], domain=ck.get("domain", ""), path=ck.get("path", "/")
            )
        except (KeyError, TypeError):
            continue
    return bool(data)


def _dump_cookies(c):
    """The session's current cookies as a list of plain dicts."""
    return [
        {"name": ck.name, "value": ck.value, "domain": ck.domain, "path": ck.path}
        for ck in c.cookies.jar
    ]


def _finalize(c, res, cookies):
    """Always hand the cookies back in the result; if `cookies` was a file path,
    also write them back to that file."""
    jar = _dump_cookies(c)
    res["session_cookies"] = jar
    if isinstance(cookies, str):
        # Owner-only (0600): the cookie jar is a session credential.
        fd = os.open(cookies, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(jar, f)
    return res


def _make_otp_source(secret, code):
    """A callable that returns the OTP to submit for MFA: a precomputed `code`
    used as-is, or one generated from the Base32 `secret` via pyotp at use-time.
    Returns None if neither was supplied."""
    if code is not None:
        text = str(code)
        return lambda: text
    if secret:
        norm = secret.upper().replace(" ", "")

        def generate():
            import pyotp  # only needed on the MFA path

            return pyotp.TOTP(norm).now()

        return generate
    return None


# --- public entry point -----------------------------------------------------
def login(
    authorize_url,
    username=None,
    password=None,
    totp_secret=None,
    totp_code=None,
    code_verifier=None,
    token_url=None,
    client_id=None,
    redirect_uri=None,
    callback=None,
    ms_redirect=False,
    cookies=".ms_session.json",
    debug_dump=None,
    interactive=False,
    push=False,
    on_push=None,
    push_timeout=120,
    push_interval=3,
    mfa=None,
):
    """Drive `authorize_url` through Microsoft and return a dict.

    Two modes:
      * default (OAuth code): returns
            {code, code_verifier, state, callback_url, access_token, tokens}
        `callback_url` is BUILT not sent (pass `callback` for your own base).
        `tokens`/`access_token` are filled only if `token_url` is given.
      * ms_redirect=True: stop at the redirect Microsoft issues back to the
        provider and return it WITHOUT following - the inner code is never
        consumed, no session is established. Returns:
            {redirect_url, code, state, session_state}

    Cookies (silent SSO reuse) work in or out, file or inline:
      * `cookies` may be a **file path** (loaded on entry, written back on exit),
        an **inline list** of cookie dicts (seeded from memory, nothing written),
        or None (no seed).
      * Either way the result always includes `session_cookies` (a list of
        dicts) so you can persist them yourself instead of using a file.

    MFA: pass `totp_secret` (Base32, a fresh code is generated per attempt) or
    `totp_code` (an already-valid 6-digit code, used as-is). Only TOTP /
    authenticator-app second factors can be satisfied this way.

    `push=True` instead satisfies MFA with a **number-matching Authenticator
    push**: Microsoft shows a two-digit number and the user taps it in the app.
    `on_push(PushEvent)` receives the number (a `number_matching` event), then a
    `pending` event per poll, then a terminal `approved`; a rejection or no
    response raises `entrance.PushError`. `push_timeout` (seconds) bounds the
    wait and `push_interval` paces the poll. Prefer `entrance.push_login()` /
    `foci_login(push=True)` for the full sign-in-to-`Broker` path.

    `mfa=<MfaPrompt>` is the **interactive** second factor (see `entrance.MfaPrompt`):
    only when Microsoft asks for MFA, `mfa.choose(methods)` picks `"push"` or
    `"otp"` from what the account offers, `mfa.on_push(PushEvent)` streams the
    number to tap, `mfa.otp(attempt)` supplies an authenticator code (up to 3
    tries), and the user may switch method mid-way. It takes precedence over
    `totp_secret`/`totp_code` and can't be combined with `push=True`. Failures
    are distinct: `InvalidCredentials` (wrong password), `Unsupported` /
    `FederatedAccount` / `UnsupportedMfa` (can't be driven headlessly), `Blocked`
    (policy / Conditional Access), `PushError` (denied / timed out),
    `OtpRejected`, `MfaCancelled`.

    `password` may be an `entrance.Secret`: a one-shot holder whose value is
    dropped the moment it is submitted to Microsoft. The password is never logged,
    cached or included in an exception message or debug dump.

    client_id / redirect_uri / state default to the authorize URL's query.
    Tries the seeded cookies first (silent, no password); falls back to a
    username/password login.

    `interactive` chooses a browser fallback (see `browser_login()`):
      * `True` - try headless first; if it can't finish (no credentials,
        push/number-matching MFA, an unhandled page) open the user's own browser.
        With no username/password this goes straight to a full manual sign-in.
      * `"always"` - skip headless entirely and open the browser for a full
        manual sign-in (email, password, 2FA), even when credentials are given.
    The browser's cookies are not captured, so an interactive run returns no
    `session_cookies` and writes no cookie file.
    """
    if interactive and ms_redirect:
        raise ValueError("interactive can't be combined with ms_redirect=True")
    if push and ms_redirect:
        raise ValueError("push can't be combined with ms_redirect=True")
    if mfa is not None and (push or ms_redirect):
        raise ValueError("mfa can't be combined with push=True or ms_redirect=True")
    had_credentials = bool(username and password)
    secret = password if isinstance(password, Secret) or password is None else Secret(password)
    password = None  # from here on only the one-shot holder carries it
    push_req = (
        _PushRequest(on_event=on_push, timeout=push_timeout, interval=push_interval)
        if push or mfa is not None
        else None
    )

    def _browser_login():
        from . import _browser  # deferred: only the browser path needs it

        return _browser.browser_login(
            authorize_url,
            code_verifier=code_verifier,
            token_url=token_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            callback=callback,
        )

    # interactive="always": go straight to a full manual sign-in in the browser,
    # skipping the headless attempt even when credentials are supplied.
    if interactive == "always":
        return _browser_login()

    try:
        return _headless(
            authorize_url,
            username,
            secret,
            totp_secret,
            totp_code,
            code_verifier,
            token_url,
            client_id,
            redirect_uri,
            callback,
            ms_redirect,
            cookies,
            debug_dump,
            push_req,
            mfa,
        )
    except (LoginFailed, MfaRequired) as e:
        if not interactive:
            raise
        # A real headless failure (e.g. push MFA) is worth a note; with no
        # credentials the browser was the intended path, so stay quiet.
        if had_credentials:
            print(f"Headless sign-in didn't finish ({e}); opening the browser.", file=sys.stderr)
        return _browser_login()


def _headless(
    authorize_url,
    username,
    password,
    totp_secret,
    totp_code,
    code_verifier,
    token_url,
    client_id,
    redirect_uri,
    callback,
    ms_redirect,
    cookies,
    debug_dump,
    push_req=None,
    mfa=None,
):
    q = _q(authorize_url)
    outer_state = q.get("state")
    xchg = {
        "token_url": token_url,
        "client_id": client_id or q.get("client_id"),
        "redirect_uri": redirect_uri if redirect_uri is not None else q.get("redirect_uri"),
        "code_verifier": code_verifier,
        "callback_base": callback,
    }

    c = requests.Session(impersonate=IMPERSONATE)
    c.headers.update(BROWSER_HEADERS)
    otp_source = _make_otp_source(totp_secret, totp_code)

    # 1) silent SSO with seeded cookies (no password, no prompt=login)
    if _seed_cookies(c, cookies):
        try:
            res = _drive(
                c,
                authorize_url,
                outer_state,
                xchg,
                username,
                None,
                None,
                debug_dump,
                ms_redirect,
                push_req,
                mfa,
            )
            return _finalize(c, res, cookies)
        except NeedsCredentials:
            pass  # seed stale/expired -> full login

    # 2) full credential login
    if not (username and password):
        raise LoginFailed(
            "No saved session and nothing to sign in with. Pass username and password "
            "(plus totp_secret/totp_code for MFA), reuse a saved cookie jar via cookies=, "
            "or pass interactive=True to sign in in a browser."
        )
    res = _drive(
        c,
        authorize_url,
        outer_state,
        xchg,
        username,
        password,
        otp_source,
        debug_dump,
        ms_redirect,
        push_req,
        mfa,
    )
    return _finalize(c, res, cookies)


def _drive(
    c,
    authorize_url,
    outer_state,
    xchg,
    username,
    creds,
    otp_source,
    debug_dump,
    ms_redirect,
    push_req=None,
    mfa=None,
):
    r = c.get(authorize_url, allow_redirects=False)
    return _walk(
        c,
        r,
        outer_state,
        xchg,
        username,
        creds,
        otp_source,
        debug_dump,
        ms_redirect,
        push_req=push_req,
        mfa=mfa,
    )


def _submit_password(c, cfg, username, secret):
    ft, ctx = cfg["sFT"], cfg["sCtx"]
    if cfg.get("urlGetCredentialType"):  # refresh flow token, detect federation
        gct = c.post(
            cfg["urlGetCredentialType"],
            json={
                "username": username,
                "isOtherIdpSupported": True,
                "checkPhones": False,
                "isRemoteNGCSupported": True,
                "isFidoSupported": True,
                "originalRequest": ctx,
                "flowToken": ft,
            },
        ).json()
        fed = (gct.get("Credentials") or {}).get("FederationRedirectUrl")
        if fed:
            raise FederatedAccount("Account federated to another IdP: " + fed, redirect_url=fed)
        if gct.get("IfExistsResult") == 1:  # no such account
            raise InvalidCredentials("Wrong username or password")
        ft = gct.get("FlowToken") or ft
    pw = secret.take() if isinstance(secret, Secret) else secret
    if pw is None:
        raise LoginFailed("The sign-in page repeated after the password was submitted.")
    data = {
        "login": username,
        "loginfmt": username,
        "passwd": pw,
        "type": "11",
        "LoginOptions": "3",
        "ctx": ctx,
        "flowToken": ft,
        "canary": cfg.get("canary"),
        "ps": "2",
        "i19": "1000",
    }
    pw = None  # the form holds the only remaining reference
    try:
        return c.post(_abs(cfg["urlPost"]), data=data, allow_redirects=False)
    finally:
        data = None


def _looks_federated(url):
    """A redirect leaving Microsoft for an ADFS-style endpoint after the password."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.endswith((".microsoftonline.com", ".live.com", ".microsoft.com")):
        return False
    return "/adfs/" in parts.path.lower() or host.startswith(("adfs.", "fs.", "sts."))


def _mfa_headers(cfg):
    hdr = {}
    if cfg.get("apiCanary"):
        hdr["canary"] = cfg["apiCanary"]
    if cfg.get("correlationId"):
        hdr["client-request-id"] = cfg["correlationId"]
    return hdr


def _mfa_dump(cfg, debug_dump):
    if debug_dump:
        # Owner-only (0600): the dump contains raw auth flow tokens (sFT, sCtx, canary).
        fd = os.open(debug_dump, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(cfg, indent=2))


def _mfa_process(c, cfg, chosen, ctx, ft, otp=None):
    """The final ProcessAuth POST that turns an approved/verified second factor
    back into the login redirect. `otp` is the TOTP code (omitted for push)."""
    data = {
        "type": "19",
        "GeneralVerify": "false",
        "request": ctx,
        "ctx": ctx,
        "flowToken": ft,
        "canary": cfg.get("canary"),
        "mfaAuthMethod": chosen,
        "login": cfg.get("sPOST_Username") or "",
        "rememberMFA": "false",
    }
    if otp is not None:
        data["otc"] = otp
    return c.post(_abs(cfg["urlPost"]), data=data, allow_redirects=False)


_OFFERED = {PUSH_METHOD: PUSH, "PhoneAppOTP": OTP}
_METHOD_IDS = {v: k for k, v in _OFFERED.items()}


def _offered_methods(cfg):
    """The normalized methods ("push", "otp") the account offers, push first."""
    ids = {p.get("authMethodId") for p in cfg.get("arrUserProofs") or []}
    return [m for mid, m in _OFFERED.items() if mid in ids]


def _otp_challenge(c, cfg, mfa, hdr):
    """BeginAuth for PhoneAppOTP, then up to OTP_ATTEMPTS asks for a code. Returns
    `(ctx, flow_token, code)` for the ProcessAuth POST."""
    chosen = _METHOD_IDS[OTP]
    begin_url, end_url = _abs(cfg["urlBeginAuth"]), _abs(cfg["urlEndAuth"])
    ctx, ft = cfg["sCtx"], cfg["sFT"]
    begin = c.post(
        begin_url,
        json={"AuthMethodId": chosen, "Method": "BeginAuth", "ctx": ctx, "flowToken": ft},
        headers=hdr,
    ).json()
    if not begin.get("Success"):
        raise MfaRequired(f"BeginAuth failed: {begin.get('Message') or begin}")
    ctx, ft = begin.get("Ctx", ctx), begin.get("FlowToken", ft)
    session_id = begin.get("SessionId")
    cancelled = hook(mfa, "cancelled")
    ask = hook(mfa, "otp")
    for attempt in range(1, OTP_ATTEMPTS + 1):
        if cancelled():
            raise MfaCancelled("Sign-in cancelled")
        code = str(ask(attempt)).strip()
        end = c.post(
            end_url,
            json={
                "AuthMethodId": chosen,
                "Method": "EndAuth",
                "ctx": ctx,
                "flowToken": ft,
                "SessionId": session_id,
                "AdditionalAuthData": code,
                "PollCount": 1,
            },
            headers=hdr,
        ).json()
        ctx, ft = end.get("Ctx", ctx), end.get("FlowToken", ft)
        if end.get("Success") and end.get("ResultValue") in (None, "Success"):
            return ctx, ft, code
        code = None
    raise OtpRejected(
        f"Microsoft rejected the authenticator code {OTP_ATTEMPTS} times", attempts=OTP_ATTEMPTS
    )


def _handle_mfa_interactive(c, cfg, debug_dump, mfa, push_req):
    """Ask `mfa` which offered method to use and drive it; loop back to `choose`
    on a switch (or a denied/timed-out push / spent codes when `retry` allows)."""
    offered = _offered_methods(cfg)
    if not offered:
        _mfa_dump(cfg, debug_dump)
        ids = [p.get("authMethodId") for p in cfg.get("arrUserProofs") or []]
        raise UnsupportedMfa(
            f"No supported MFA method on this account; offered={ids}.", offered=ids
        )
    hdr = _mfa_headers(cfg)
    choose, retry = hook(mfa, "choose"), hook(mfa, "retry")
    req = _PushRequest(
        on_event=hook(mfa, "on_push"),
        timeout=push_req.timeout if push_req else 120,
        interval=push_req.interval if push_req else 3,
        should_switch=hook(mfa, "should_switch"),
        cancelled=hook(mfa, "cancelled"),
    )
    while True:
        if hook(mfa, "cancelled")():
            raise MfaCancelled("Sign-in cancelled")
        method = choose(list(offered))
        if method not in offered:
            raise UnsupportedMfa(f"Method {method!r} isn't offered; offered={offered}.")
        try:
            if method == PUSH:
                ctx, ft = run_push_challenge(c, cfg, PUSH_METHOD, hdr, req)
                return _mfa_process(c, cfg, PUSH_METHOD, ctx, ft)
            ctx, ft, code = _otp_challenge(c, cfg, mfa, hdr)
            try:
                return _mfa_process(c, cfg, _METHOD_IDS[OTP], ctx, ft, otp=code)
            finally:
                code = None
        except MfaSwitch:
            continue
        except (PushError, OtpRejected) as e:
            if not retry(e):
                raise


def _handle_mfa(c, cfg, otp_source, debug_dump, push_req=None, mfa=None):
    if mfa is not None:
        return _handle_mfa_interactive(c, cfg, debug_dump, mfa, push_req)
    proofs = cfg.get("arrUserProofs") or []
    methods = {p.get("authMethodId") for p in proofs}

    # Number-matching Authenticator push: surface the tap number and poll.
    if push_req is not None:
        if PUSH_METHOD not in methods:
            _mfa_dump(cfg, debug_dump)
            raise MfaRequired(
                f"No Authenticator push method on this account; offered={methods}. "
                "Use totp_secret/totp_code, or enroll Authenticator push."
            )
        ctx, ft = run_push_challenge(c, cfg, PUSH_METHOD, _mfa_headers(cfg), push_req)
        return _mfa_process(c, cfg, PUSH_METHOD, ctx, ft)

    chosen = next((m for m in _TOTP_METHODS if m in methods), None)
    if not chosen:
        _mfa_dump(cfg, debug_dump)
        raise MfaRequired(
            f"No TOTP method on this account; offered={methods}. "
            "Enroll an authenticator app (PhoneAppOTP), or pass push=True for "
            "number-matching Authenticator push."
        )
    if otp_source is None:
        raise MfaRequired("MFA required but no TOTP secret/code was provided.")

    begin_url, end_url = _abs(cfg["urlBeginAuth"]), _abs(cfg["urlEndAuth"])
    ctx, ft = cfg["sCtx"], cfg["sFT"]
    hdr = _mfa_headers(cfg)

    begin = c.post(
        begin_url,
        json={
            "AuthMethodId": chosen,
            "Method": "BeginAuth",
            "ctx": ctx,
            "flowToken": ft,
        },
        headers=hdr,
    ).json()
    if not begin.get("Success"):
        raise MfaRequired(f"BeginAuth failed: {begin.get('Message') or begin}")
    ctx, ft = begin.get("Ctx", ctx), begin.get("FlowToken", ft)
    session_id = begin.get("SessionId")

    otp = otp_source()
    end = c.post(
        end_url,
        json={
            "AuthMethodId": chosen,
            "Method": "EndAuth",
            "ctx": ctx,
            "flowToken": ft,
            "SessionId": session_id,
            "AdditionalAuthData": otp,
            "PollCount": 1,
        },
        headers=hdr,
    ).json()
    if not end.get("Success") or end.get("ResultValue") not in (None, "Success"):
        raise MfaRequired(f"EndAuth/OTP rejected: {end.get('ResultValue') or end}")
    ctx, ft = end.get("Ctx", ctx), end.get("FlowToken", ft)

    return _mfa_process(c, cfg, chosen, ctx, ft, otp=otp)


def _walk(
    c,
    r,
    outer_state,
    xchg,
    username,
    creds,
    otp_source,
    debug_dump,
    ms_redirect=False,
    hops=0,
    injected=False,
    pw_done=False,
    push_req=None,
    mfa=None,
):
    if hops > 20:
        raise LoginFailed("Too many hops without reaching the callback code.")

    def rec(resp, **kw):
        return _walk(
            c,
            resp,
            outer_state,
            xchg,
            username,
            creds,
            otp_source,
            debug_dump,
            ms_redirect=ms_redirect,
            hops=hops + 1,
            injected=kw.get("injected", injected),
            pw_done=kw.get("pw_done", pw_done),
            push_req=push_req,
            mfa=mfa,
        )

    # --- redirect hop ---
    if _is_redirect(r):
        loc = urljoin(r.url, r.headers["location"])
        q = _q(loc)
        if q.get("error"):
            desc = q.get("error_description", q["error"])
            _raise_entra_error(_aadsts(desc), desc, prefix="OAuth error")
        # ms_redirect: stop at the redirect leaving Microsoft back to the
        # provider, carrying the (inner) code - don't follow it.
        if (
            ms_redirect
            and "login.microsoftonline.com" in str(r.url)
            and "login.microsoftonline.com" not in loc
            and q.get("code")
        ):
            return {
                "redirect_url": loc,
                "code": q.get("code"),
                "state": q.get("state"),
                "session_state": q.get("session_state"),
            }
        if not ms_redirect and q.get("code") and q.get("state") == outer_state:
            return _finish(c, q["code"], q["state"], xchg, intercepted=loc)
        if creds is not None and pw_done and _looks_federated(loc):
            raise FederatedAccount(redirect_url=loc.split("?", 1)[0])
        # entering Entra's authorize endpoint: add login_hint; force fresh creds
        # only when we have a password (silent reuse must NOT send prompt=login)
        if (
            not injected
            and "login.microsoftonline.com" in loc
            and "/authorize" in loc
            and "login_hint" not in loc
        ):
            extra = {"login_hint": username} if username else {}
            if creds is not None:
                extra["prompt"] = "login"
            if extra:
                loc = _add_params(loc, **extra)
            injected = True
        return rec(c.get(loc, allow_redirects=False), injected=injected)

    # --- HTML page hop ---
    cfg = parse_config(r.text)
    if cfg and "sFT" in cfg:
        url_post = str(cfg.get("urlPost", ""))
        err = str(cfg.get("sErrorCode") or "")

        if cfg.get("urlGetCredentialType"):  # username/password page
            if creds is None:
                raise NeedsCredentials()  # silent seed didn't authenticate
            if pw_done and err not in ("", "0", "16000"):
                _raise_entra_error(
                    err,
                    cfg.get("strServiceExceptionMessage")
                    or cfg.get("sErrTxt")
                    or "wrong password?",
                    prefix="Login rejected",
                )
            return rec(_submit_password(c, cfg, username, creds), pw_done=True)

        if cfg.get("urlBeginAuth") or err in _MFA_CODES:  # MFA challenge
            return rec(_handle_mfa(c, cfg, otp_source, debug_dump, push_req, mfa))

        if url_post.rstrip("/").endswith("kmsi"):  # "Stay signed in?"
            return rec(
                c.post(
                    _abs(url_post),
                    data={
                        "LoginOptions": "1",
                        "ctx": cfg["sCtx"],
                        "flowToken": cfg["sFT"],
                        "canary": cfg.get("canary"),
                        "i19": "1000",
                    },
                    allow_redirects=False,
                )
            )

        if err and err not in ("0", "16000"):
            _raise_entra_error(err, cfg.get("strServiceExceptionMessage") or cfg.get("sErrTxt"))

    # form_post bounce (a self-submitting <form> back to the provider)
    form = re.search(r'<form[^>]+action="([^"]+)"', r.text)
    if form:
        hidden = dict(re.findall(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', r.text))
        if hidden.get("code") and hidden.get("state") == outer_state:
            action = _add_params(
                urljoin(r.url, form.group(1)), code=hidden["code"], state=hidden.get("state", "")
            )
            return _finish(c, hidden["code"], hidden.get("state"), xchg, intercepted=action)
        return rec(c.post(urljoin(r.url, form.group(1)), data=hidden, allow_redirects=False))

    if creds is None:
        raise NeedsCredentials()  # silent attempt fell through -> need login
    if debug_dump:
        # Owner-only (0600): the dump may contain sensitive page content.
        fd = os.open(debug_dump, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(r.text)
    raise LoginFailed(
        "Stuck on a page with no form/redirect - UI changed or an unhandled challenge."
    )


def _finish(c, code, state, xchg, intercepted=None):
    base = xchg.get("callback_base")
    callback_url = _add_params(base, code=code, state=state) if base else intercepted
    tokens = _exchange(c, code, xchg) if xchg.get("token_url") else None
    return _result(code, xchg.get("code_verifier"), state, tokens, callback_url)


def _result(code, code_verifier, state, tokens, callback_url):
    return {
        "code": code,  # raw authorization code at the callback
        "code_verifier": code_verifier,  # pair with `code` to exchange elsewhere
        "state": state,
        "callback_url": callback_url,  # built, NOT sent - yours to forward
        "access_token": (tokens or {}).get("access_token"),
        "tokens": tokens,  # full token-endpoint response (or None)
    }


def _exchange(c, code, xchg):
    data = {"grant_type": "authorization_code", "code": code, "client_id": xchg.get("client_id")}
    if xchg.get("code_verifier"):
        data["code_verifier"] = xchg["code_verifier"]
    if xchg.get("redirect_uri"):
        data["redirect_uri"] = xchg["redirect_uri"]
    resp = c.post(xchg["token_url"], data=data)
    try:
        return resp.json()
    except ValueError:
        raise LoginFailed(
            f"Token endpoint non-JSON ({resp.status_code}): {resp.text[:300]}"
        ) from None
