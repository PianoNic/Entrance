"""
Get a Schulnetz token/session headlessly — no hosted endpoint, no browser.

Both targets return only the Microsoft redirect (the inner code Microsoft hands
back to the provider), intercepted before it is consumed — no token exchange,
no session. They differ only by entry point:
  * mobile -> authorize.php (PKCE)  => {redirect_url, code, state, code_verifier}
  * web    -> the school root /     => {redirect_url, code, state, session_state}

Each drives the Microsoft login via entrance; the shared cookie jar makes
repeat logins password-free.

Creds come from .env: SN_USER / SN_PASS / SN_TOTP

Usage:
    python main.py            # both
    python main.py mobile     # tokens only
    python main.py web        # PHP session only
"""

import os
import sys
import base64
import hashlib
import secrets
import string
from urllib.parse import urlencode

import entrance

# --- config (edit here) -----------------------------------------------------
BASE_URL = "https://schulnetz.bbbaden.ch"
CLIENT_ID = "ppyybShnMerHdtBQ"
COOKIE_FILE = ".ms_session.json"


def load_dotenv(path=".env"):
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _rand(n):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def build_authorize_url():
    """Fresh PKCE authorize URL for Schulnetz. Returns (url, code_verifier, state)."""
    verifier = _rand(128)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = _rand(32)
    params = {
        "response_type": "code", "client_id": CLIENT_ID, "state": state,
        "redirect_uri": "", "scope": "openid ", "nonce": _rand(32),
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    return f"{BASE_URL}/authorize.php?{urlencode(params)}", verifier, state


def get_mobile_redirect(user, pw, totp):
    """Mobile flow: the Microsoft redirect back to the provider (inner code) for
    the authorize.php entry. Includes the PKCE code_verifier for a later token
    exchange. Returns {redirect_url, code, state, session_state, code_verifier}."""
    url, verifier, _ = build_authorize_url()
    res = entrance.login(url, user, pw, totp, ms_redirect=True, cookie_file=COOKIE_FILE)
    res["code_verifier"] = verifier
    return res


def get_web_redirect(user, pw, totp):
    """Web flow: the Microsoft redirect back to the provider (inner code) for the
    root entry. Returns {redirect_url, code, state, session_state}."""
    return entrance.login(f"{BASE_URL}/", user, pw, totp,
                          ms_redirect=True, cookie_file=COOKIE_FILE)


def creds():
    load_dotenv()
    user = os.environ.get("SN_USER")
    pw = os.environ.get("SN_PASS")
    totp = os.environ.get("SN_TOTP")
    if not user:
        import getpass
        user = input("User: ").strip()
        pw = getpass.getpass("Password: ")
    return user, pw, totp


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    user, pw, totp = creds()

    try:
        if mode in ("mobile", "both"):
            m = get_mobile_redirect(user, pw, totp)
            print("MOBILE (Microsoft redirect):")
            print("  redirect_url  :", m["redirect_url"])
            print("  code          :", m["code"])
            print("  state         :", m["state"])
            print("  session_state :", m["session_state"])
            print("  code_verifier :", m["code_verifier"])

        if mode in ("web", "both"):
            s = get_web_redirect(user, pw, totp)
            print("WEB (Microsoft redirect):")
            print("  redirect_url  :", s["redirect_url"])
            print("  code          :", s["code"])
            print("  state         :", s["state"])
            print("  session_state :", s["session_state"])
    except entrance.MfaRequired as e:
        print("MFA:", e)
        return 1
    except entrance.LoginFailed as e:
        print("Failed:", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
