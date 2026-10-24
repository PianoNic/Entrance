"""Interactive sign-in in the user's own browser, for what headless can't do
(push / number-matching MFA, unhandled interstitials, passkeys).

The authorize URL opens in the default browser and the authorization code
comes back to the library one of two ways:

  * **loopback** - the redirect_uri is `http://localhost[:port]/...`: a tiny
    local HTTP server receives the redirect itself (like `az login`).
  * **paste** - any other redirect_uri (e.g. Microsoft's `.../nativeclient`):
    the user copies the final URL from the address bar and pastes it back.

Either way only the code comes back, never the browser's cookies, so there is
no silent cookie reuse afterwards - persist the tokens instead.
"""

import select
import socket
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from curl_cffi import requests

from ._client import BROWSER_HEADERS, IMPERSONATE, LoginFailed, _finish, _q

_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")
_DONE_PAGE = (
    b"<!doctype html><meta charset=utf-8><title>Signed in</title>"
    b"<body style='font-family:system-ui;margin:3em'><h2>Signed in</h2>"
    b"<p>You can close this tab and return to the terminal.</p>"
)
_FAIL_PAGE = (
    b"<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
    b"<body style='font-family:system-ui;margin:3em'><h2>Sign-in failed</h2>"
    b"<p>Check the terminal for details.</p>"
)


def is_loopback(redirect_uri):
    """True for an `http://localhost[:port]` style redirect the library can
    receive itself."""
    if not redirect_uri:
        return False
    u = urlsplit(redirect_uri)
    return u.scheme == "http" and (u.hostname or "") in _LOOPBACK_HOSTS


def _with_query(url, **params):
    """`url` with the given query parameters replaced."""
    u = urlsplit(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q.update(params)
    return urlunsplit(u._replace(query=urlencode(q)))


def _params_from(text):
    """Code/state/error from a pasted callback URL (query or fragment), or a
    bare code."""
    text = text.strip().strip('"').strip("'")
    if "://" not in text and "=" not in text:
        return {"code": text}  # just the code
    u = urlsplit(text)
    params = dict(parse_qsl(u.query))
    params.update(parse_qsl(u.fragment))  # response_mode=fragment
    if not u.scheme:  # pasted "code=...&state=..." without the URL
        params.update(parse_qsl(text))
    return params


class _Catcher(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        params = dict(parse_qsl(urlsplit(self.path).query))
        if "code" not in params and "error" not in params:
            self.send_response(404)  # favicon & friends
            self.end_headers()
            return
        self.server.result = params  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_DONE_PAGE if "code" in params else _FAIL_PAGE)

    def log_message(self, *args):  # keep the terminal quiet
        pass


class _Server(HTTPServer):
    result = None


class _Server6(_Server):
    address_family = socket.AF_INET6


def _bind(redirect_uri):
    """Servers listening for `redirect_uri`, and the redirect_uri to send.
    `localhost` is served on both 127.0.0.1 and ::1 (browsers may try either
    first). With no port in the URI a free one is picked - Entra accepts any
    port for a registered `http://localhost`."""
    u = urlsplit(redirect_uri)
    if u.hostname in ("::1", "[::1]"):
        servers = [_Server6(("::1", u.port or 0), _Catcher)]
    else:
        servers = [_Server(("127.0.0.1", u.port or 0), _Catcher)]
        if u.hostname == "localhost":
            try:
                servers.append(_Server6(("::1", servers[0].server_address[1]), _Catcher))
            except OSError:
                pass  # no IPv6 loopback; 127.0.0.1 alone is fine
    if not u.port:
        netloc = f"{u.hostname}:{servers[0].server_address[1]}"
        redirect_uri = urlunsplit(u._replace(netloc=netloc))
    return servers, redirect_uri


def _wait_loopback(servers, timeout):
    """Serve until one server got the callback, or `timeout` seconds."""
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select(servers, [], [], 0.25)
            for srv in ready:
                srv.handle_request()
                if srv.result is not None:
                    return srv.result
    finally:
        for srv in servers:
            srv.server_close()
    raise LoginFailed(f"No sign-in came back to the browser callback within {timeout}s.")


def _say(msg):
    print(msg, file=sys.stderr, flush=True)


def browser_login(
    authorize_url,
    code_verifier=None,
    token_url=None,
    client_id=None,
    redirect_uri=None,
    callback=None,
    *,
    timeout=300,
    open_browser=None,
    prompt=None,
):
    """Sign in through the user's own browser and return the same dict as
    `login()`: {code, code_verifier, state, callback_url, access_token,
    tokens, mode, session_cookies}.

    The redirect_uri (from the authorize URL unless given) picks the mode:
    `http://localhost...` -> **loopback** (a local server catches the code;
    a missing port is filled with a free one), anything else -> **paste**
    (the user pastes the final URL, or just the code, back in).

    `open_browser(url)` defaults to `webbrowser.open`; `prompt(text)`
    (paste mode) defaults to `input`. `timeout` bounds the loopback wait.
    `session_cookies` is always [] - the browser's cookies stay in the browser.
    """
    q = _q(authorize_url)
    outer_state = q.get("state")
    redirect_uri = redirect_uri or q.get("redirect_uri")
    open_browser = open_browser or webbrowser.open

    if is_loopback(redirect_uri):
        mode = "loopback"
        servers, redirect_uri = _bind(redirect_uri)
        if redirect_uri != q.get("redirect_uri"):
            authorize_url = _with_query(authorize_url, redirect_uri=redirect_uri)
        _say(f"Opening your browser to sign in. If it doesn't open, visit:\n{authorize_url}")
        try:
            open_browser(authorize_url)
        except Exception:  # noqa: BLE001 - the printed link is the fallback
            pass
        params = _wait_loopback(servers, timeout)
        intercepted = _with_query(redirect_uri, **params)
    else:
        mode = "paste"
        _say(
            "Opening your browser to sign in. If it doesn't open, visit:\n"
            f"{authorize_url}\n\n"
            "After signing in you land on a page that may look blank or show an\n"
            "error - that's expected. Copy the full URL from the address bar."
        )
        try:
            open_browser(authorize_url)
        except Exception:  # noqa: BLE001
            pass
        pasted = (prompt or input)("Paste the URL here: ")
        params = _params_from(pasted or "")
        intercepted = pasted.strip() if pasted and "://" in pasted else None

    if params.get("error"):
        detail = params.get("error_description") or ""
        raise LoginFailed(f"Sign-in failed: {params['error']}: {detail}".rstrip(": "))
    code = params.get("code")
    if not code:
        raise LoginFailed("No authorization code in what came back from the browser.")
    state = params.get("state")
    if outer_state and state and state != outer_state:
        raise LoginFailed("State mismatch - the callback is not from this sign-in.")

    xchg = {
        "token_url": token_url,
        "client_id": client_id or q.get("client_id"),
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "callback_base": callback,
    }
    c = requests.Session(impersonate=IMPERSONATE)
    c.headers.update(BROWSER_HEADERS)
    res = _finish(c, code, state or outer_state, xchg, intercepted=intercepted)
    res["mode"] = mode
    res["redirect_uri"] = redirect_uri  # may differ from the URL's (port filled in)
    res["session_cookies"] = []
    return res
