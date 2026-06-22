"""
Headless login for any OAuth2 provider that federates to Microsoft Entra.

Give it an authorize URL — the kind your provider hands you to open in a
browser — and it drives the Microsoft sign-in over pure HTTP (no browser),
intercepts the authorization `code` at the callback, and optionally exchanges
it for tokens.

Knows nothing about any specific provider: client_id / redirect_uri / state are
read from the authorize URL; the token endpoint is whatever you pass in.
"""

import os
import re
import json
from urllib.parse import urljoin, urlencode, urlsplit, urlunsplit, parse_qsl

from curl_cffi import requests

IMPERSONATE = "chrome"
# ponytail: ESTS serves a JS-only Chrome-SSO "pull" page (hpgid=6, no sFT) to
# *Google Chrome* (which supports the BSSO extension) but the plain credential
# page (hpgid=1104, has sFT) to other Chromium browsers. Impersonating Opera —
# a non-Chrome Chromium — skips the un-replayable SSO-pull step entirely.
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

_TOTP_METHODS = ("PhoneAppOTP",)          # authenticator-app OTP
_MFA_CODES = {"50074", "50076", "50079", "500121", "50072"}


class MfaRequired(RuntimeError):
    pass


class LoginFailed(RuntimeError):
    pass


class NeedsCredentials(RuntimeError):
    """Silent (cookie-jar) attempt didn't authenticate — fall back to password."""


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
                    yield text[start:i + 1]
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


# --- cookie jar persistence (enables silent SSO reuse) ----------------------
def _load_jar(c, path):
    if not path or not os.path.exists(path):
        return False
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (ValueError, OSError):
        return False
    for ck in data:
        try:
            c.cookies.set(ck["name"], ck["value"],
                          domain=ck.get("domain", ""), path=ck.get("path", "/"))
        except Exception:
            pass
    return bool(data)


def _save_jar(c, path):
    if not path:
        return
    out = [{"name": ck.name, "value": ck.value, "domain": ck.domain, "path": ck.path}
           for ck in c.cookies.jar]
    json.dump(out, open(path, "w", encoding="utf-8"))


# --- public entry point -----------------------------------------------------
def login(authorize_url, username=None, password=None, totp_secret=None,
          code_verifier=None, token_url=None, client_id=None, redirect_uri=None,
          callback=None, ms_redirect=False, cookie_file=".ms_session.json",
          debug_dump=None):
    """Drive `authorize_url` through Microsoft and return a dict.

    Two modes:
      * default (OAuth code): returns
            {code, code_verifier, state, callback_url, access_token, tokens}
        `callback_url` is BUILT not sent (pass `callback` for your own base).
        `tokens`/`access_token` are filled only if `token_url` is given.
      * ms_redirect=True: stop at the redirect Microsoft issues back to the
        provider and return it WITHOUT following — the inner code is never
        consumed, no session is established. Returns:
            {redirect_url, code, state, session_state}

    client_id / redirect_uri / state default to the authorize URL's query.
    Tries the saved cookie jar first (silent, no password); falls back to a
    username/password login and re-saves the jar.
    """
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

    # 1) silent SSO with a saved jar (no password, no prompt=login)
    if _load_jar(c, cookie_file):
        try:
            res = _drive(c, authorize_url, outer_state, xchg, username, None,
                         None, debug_dump, ms_redirect)
            _save_jar(c, cookie_file)
            return res
        except NeedsCredentials:
            pass                                # jar stale/expired -> full login

    # 2) full credential login, then save the fresh authenticated jar
    if not (username and password):
        raise LoginFailed("No valid session in the jar and no username/password "
                          "to log in with.")
    res = _drive(c, authorize_url, outer_state, xchg, username, password,
                 totp_secret, debug_dump, ms_redirect)
    _save_jar(c, cookie_file)
    return res


def _drive(c, authorize_url, outer_state, xchg, username, creds, totp_secret,
           debug_dump, ms_redirect):
    r = c.get(authorize_url, allow_redirects=False)
    return _walk(c, r, outer_state, xchg, username, creds, totp_secret,
                 debug_dump, ms_redirect)


def _submit_password(c, cfg, username, password):
    ft, ctx = cfg["sFT"], cfg["sCtx"]
    if cfg.get("urlGetCredentialType"):                 # refresh flow token, detect federation
        gct = c.post(cfg["urlGetCredentialType"], json={
            "username": username, "isOtherIdpSupported": True, "checkPhones": False,
            "isRemoteNGCSupported": True, "isFidoSupported": True,
            "originalRequest": ctx, "flowToken": ft,
        }).json()
        if (gct.get("Credentials") or {}).get("FederationRedirectUrl"):
            raise LoginFailed("Account federated to another IdP: "
                              + gct["Credentials"]["FederationRedirectUrl"])
        ft = gct.get("FlowToken") or ft
    return c.post(_abs(cfg["urlPost"]), data={
        "login": username, "loginfmt": username, "passwd": password,
        "type": "11", "LoginOptions": "3", "ctx": ctx, "flowToken": ft,
        "canary": cfg.get("canary"), "ps": "2", "i19": "1000",
    }, allow_redirects=False)


def _handle_mfa(c, cfg, totp_secret, debug_dump):
    import pyotp                                        # only needed on the MFA path
    proofs = cfg.get("arrUserProofs") or []
    methods = {p.get("authMethodId") for p in proofs}
    chosen = next((m for m in _TOTP_METHODS if m in methods), None)
    if not chosen:
        if debug_dump:
            open(debug_dump, "w", encoding="utf-8").write(json.dumps(cfg, indent=2))
        raise MfaRequired(f"No TOTP method on this account; offered={methods}. "
                          "Enroll an authenticator app (PhoneAppOTP).")
    if not totp_secret:
        raise MfaRequired("MFA required but no TOTP secret was provided.")

    begin_url, end_url = _abs(cfg["urlBeginAuth"]), _abs(cfg["urlEndAuth"])
    process_url = _abs(cfg["urlPost"])
    ctx, ft = cfg["sCtx"], cfg["sFT"]
    hdr = {}
    if cfg.get("apiCanary"):
        hdr["canary"] = cfg["apiCanary"]
    if cfg.get("correlationId"):
        hdr["client-request-id"] = cfg["correlationId"]

    begin = c.post(begin_url, json={
        "AuthMethodId": chosen, "Method": "BeginAuth", "ctx": ctx, "flowToken": ft,
    }, headers=hdr).json()
    if not begin.get("Success"):
        raise MfaRequired(f"BeginAuth failed: {begin.get('Message') or begin}")
    ctx, ft = begin.get("Ctx", ctx), begin.get("FlowToken", ft)
    session_id = begin.get("SessionId")

    otp = pyotp.TOTP(totp_secret.upper().replace(" ", "")).now()
    end = c.post(end_url, json={
        "AuthMethodId": chosen, "Method": "EndAuth", "ctx": ctx, "flowToken": ft,
        "SessionId": session_id, "AdditionalAuthData": otp, "PollCount": 1,
    }, headers=hdr).json()
    if not end.get("Success") or end.get("ResultValue") not in (None, "Success"):
        raise MfaRequired(f"EndAuth/OTP rejected: {end.get('ResultValue') or end}")
    ctx, ft = end.get("Ctx", ctx), end.get("FlowToken", ft)

    return c.post(process_url, data={
        "type": "19", "GeneralVerify": "false", "request": ctx, "ctx": ctx,
        "flowToken": ft, "canary": cfg.get("canary"), "mfaAuthMethod": chosen,
        "otc": otp, "login": cfg.get("sPOST_Username") or "", "rememberMFA": "false",
    }, allow_redirects=False)


def _walk(c, r, outer_state, xchg, username, creds, totp_secret, debug_dump,
          ms_redirect=False, hops=0, injected=False, pw_done=False):
    if hops > 20:
        raise LoginFailed("Too many hops without reaching the callback code.")
    rec = lambda resp, **kw: _walk(c, resp, outer_state, xchg, username, creds,
                                   totp_secret, debug_dump,
                                   ms_redirect=ms_redirect, hops=hops + 1,
                                   injected=kw.get("injected", injected),
                                   pw_done=kw.get("pw_done", pw_done))

    # --- redirect hop ---
    if _is_redirect(r):
        loc = urljoin(r.url, r.headers["location"])
        q = _q(loc)
        if q.get("error"):
            raise LoginFailed("OAuth error: " + q.get("error_description", q["error"]))
        # ms_redirect: stop at the redirect leaving Microsoft back to the
        # provider, carrying the (inner) code — don't follow it.
        if ms_redirect and "login.microsoftonline.com" in str(r.url) \
                and "login.microsoftonline.com" not in loc and q.get("code"):
            return {"redirect_url": loc, "code": q.get("code"),
                    "state": q.get("state"), "session_state": q.get("session_state")}
        if not ms_redirect and q.get("code") and q.get("state") == outer_state:
            return _finish(c, q["code"], q["state"], xchg, intercepted=loc)
        # entering Entra's authorize endpoint: add login_hint; force fresh creds
        # only when we have a password (silent jar reuse must NOT send prompt=login)
        if (not injected and "login.microsoftonline.com" in loc
                and "/authorize" in loc and "login_hint" not in loc):
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

        if cfg.get("urlGetCredentialType"):               # username/password page
            if creds is None:
                raise NeedsCredentials()                  # silent jar didn't authenticate
            if pw_done and err not in ("", "0", "16000"):
                raise LoginFailed(f"Login rejected (sErrorCode={err}): "
                                  + str(cfg.get("strServiceExceptionMessage")
                                        or cfg.get("sErrTxt") or "wrong password?"))
            return rec(_submit_password(c, cfg, username, creds), pw_done=True)

        if cfg.get("urlBeginAuth") or err in _MFA_CODES:  # MFA challenge
            return rec(_handle_mfa(c, cfg, totp_secret, debug_dump))

        if url_post.rstrip("/").endswith("kmsi"):          # "Stay signed in?"
            return rec(c.post(_abs(url_post), data={
                "LoginOptions": "1", "ctx": cfg["sCtx"], "flowToken": cfg["sFT"],
                "canary": cfg.get("canary"), "i19": "1000",
            }, allow_redirects=False))

        if err and err not in ("0", "16000"):
            raise LoginFailed(f"Entra error sErrorCode={err}: "
                              + str(cfg.get("strServiceExceptionMessage")
                                    or cfg.get("sErrTxt")))

    # form_post bounce (a self-submitting <form> back to the provider)
    form = re.search(r'<form[^>]+action="([^"]+)"', r.text)
    if form:
        hidden = dict(re.findall(
            r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', r.text))
        if hidden.get("code") and hidden.get("state") == outer_state:
            action = _add_params(urljoin(r.url, form.group(1)),
                                 code=hidden["code"], state=hidden.get("state", ""))
            return _finish(c, hidden["code"], hidden.get("state"), xchg, intercepted=action)
        return rec(c.post(urljoin(r.url, form.group(1)), data=hidden,
                          allow_redirects=False))

    if creds is None:
        raise NeedsCredentials()        # silent attempt fell through -> need login
    if debug_dump:
        open(debug_dump, "w", encoding="utf-8").write(r.text)
    raise LoginFailed("Stuck on a page with no form/redirect — UI changed or an "
                      "unhandled challenge.")


def _finish(c, code, state, xchg, intercepted=None):
    base = xchg.get("callback_base")
    callback_url = _add_params(base, code=code, state=state) if base else intercepted
    tokens = _exchange(c, code, xchg) if xchg.get("token_url") else None
    return _result(code, xchg.get("code_verifier"), state, tokens, callback_url)


def _result(code, code_verifier, state, tokens, callback_url):
    return {
        "code": code,                       # raw authorization code at the callback
        "code_verifier": code_verifier,     # pair with `code` to exchange elsewhere
        "state": state,
        "callback_url": callback_url,       # built, NOT sent — yours to forward
        "access_token": (tokens or {}).get("access_token"),
        "tokens": tokens,                   # full token-endpoint response (or None)
    }


def _exchange(c, code, xchg):
    data = {"grant_type": "authorization_code", "code": code,
            "client_id": xchg.get("client_id")}
    if xchg.get("code_verifier"):
        data["code_verifier"] = xchg["code_verifier"]
    if xchg.get("redirect_uri"):
        data["redirect_uri"] = xchg["redirect_uri"]
    resp = c.post(xchg["token_url"], data=data)
    try:
        return resp.json()
    except ValueError:
        raise LoginFailed(f"Token endpoint non-JSON ({resp.status_code}): "
                          f"{resp.text[:300]}")
