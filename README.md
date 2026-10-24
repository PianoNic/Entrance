# <p align="center">Entrance</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/PianoNic/Entrance/refs/heads/main/assets/entrance-icon.svg" width="150" alt="Entrance Logo">
</p>
<p align="center">
  <strong>Your headless entrance to Microsoft Entra.</strong><br>
  Browser-grade OAuth login for any Microsoft-federated provider - without a browser.
</p>
<p align="center">
  <a href="https://github.com/PianoNic/Entrance"><img src="https://badgetrack.pianonic.ch/badge?tag=entrance&label=visits&color=0078D4&style=flat" alt="visits"/></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-0078D4" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/browser-not%20required-0078D4" alt="No browser"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-0078D4" alt="MIT license"/></a>
</p>

> [!WARNING]
> **For educational and research purposes only.** Use it solely against **accounts you own** or with the **explicit authorization** of the account/tenant owner. It drives a real sign-in with real credentials - treat the cookie jar and any tokens like passwords. See the [Disclaimer](#disclaimer) below.

## About The Project

Plenty of services hand you an OAuth "open this URL in a browser to log in" link and federate the actual authentication to **Microsoft Entra**. `entrance` walks that flow for you over pure HTTP - no Playwright, no headless Chromium, no Selenium - and hands back the authorization `code` (or exchanged tokens). Point it at any authorize URL that ends up at `login.microsoftonline.com` and it logs in, handles MFA, and returns.

The whole thing is one small module and two dependencies.

## How It Works

The trick that makes browserless login actually work against a modern Entra tenant:

- **Impersonate Opera, not Chrome.** Entra serves a JavaScript-only "Chrome SSO pull" page (un-replayable without a real browser) when it sees a *Google Chrome* user-agent. Tell it you're **Opera** - a non-Chrome Chromium - and it serves the plain credential page instead, which *is* replayable.
- **Real browser fingerprint.** [`curl_cffi`](https://github.com/lexiforest/curl_cffi) replays a genuine browser TLS/JA3 fingerprint, so Entra's edge sees a browser at the wire level.
- **Replay the login XHRs by hand** - `GetCredentialType` → `login` → "Stay signed in?". For MFA, the `SAS/BeginAuth` + `SAS/EndAuth` pair with a **TOTP** code computed via [`pyotp`](https://github.com/pyauth/pyotp).
- **Intercept the code** at the callback redirect - it's read off the `Location` header and never actually delivered.
- **Silent reuse.** The Microsoft session cookie jar is persisted, so the next run logs in with no password (and no MFA prompt) until it expires.

## Features

- 🚪 **No browser** - pure HTTP, drives `login.microsoftonline.com` directly
- 🌐 **Provider-agnostic** - give it any OAuth2 authorize URL federated to Entra
- 🔐 **Headless MFA** - TOTP second factor solved automatically from your authenticator secret
- 🙋 **Browser fallback** - `interactive=True` opens the real browser for what headless can't do (push / number-matching MFA, passkeys), and catches the code via a localhost server or copy-paste
- 🍪 **Silent SSO** - persisted cookie jar means password-free reruns
- 🎛️ **Three return modes** - the raw `code`, exchanged `access_token`, or just the Microsoft redirect
- 📦 **Tiny** - one module, `curl_cffi` + `pyotp`

## Installation

```bash
pip install ms-entrance
# or
uv add ms-entrance
```

The import name is `entrance` (e.g. `from entrance import login`). Requires Python 3.10+; `curl_cffi` and `pyotp` are pulled in automatically.

## Quickstart

```python
from entrance import login

# Intercept the authorization code from any Entra-federated authorize URL
res = login(
    "https://provider.example/authorize?client_id=...&state=...&code_challenge=...",
    username="you@school.ch",
    password="...",
    totp_secret="JBSWY3DPEHPK3PXP",   # optional - only if the account has TOTP MFA
)

print(res["code"])           # the authorization code (intercepted at the callback)
print(res["callback_url"])   # the full callback URL - built, NOT sent
```

**MFA, two ways.** Pass `totp_secret` (Base32 - a fresh code is generated each
attempt) **or** `totp_code` if you already hold a valid 6-digit code from your
own authenticator:

```python
login(authorize_url, "you@school.ch", "...", totp_secret="JBSWY3DPEHPK3PXP")
login(authorize_url, "you@school.ch", "...", totp_code="123456")  # used as-is
```

**Exchange the code for tokens** - pass a `token_url` and it does the OAuth exchange for you:

```python
res = login(authorize_url, "you@school.ch", "...",
            code_verifier=verifier, token_url="https://provider.example/token")
print(res["access_token"])
```

**Just the Microsoft handoff** - stop at the redirect Microsoft issues back to the provider, untouched:

```python
res = login("https://provider.example/", "you@school.ch", "...", ms_redirect=True)
print(res["redirect_url"])   # https://provider.example/?code=...&state=...&session_state=...
```

**Silent reuse** - the first call saves `.ms_session.json`; every call after that skips the password:

```python
login(authorize_url, "you@school.ch", "...")   # full login, saves the jar
login(authorize_url)                            # silent - no password, no MFA
```

**Cookies your way - file or inline.** `cookies` takes a file path (loaded on
entry, written back on exit), an inline list of cookie dicts, or `None`. Either
way the result always carries `session_cookies`, so you can store them yourself
instead of touching disk:

```python
# inline in, inline out - nothing written to disk
res = login(authorize_url, "you@school.ch", "...", cookies=None)
jar = res["session_cookies"]                    # list of {name, value, domain, path}

# later, seed straight from memory (or your own DB/secret store)
res = login(authorize_url, cookies=jar)         # silent, no file involved
```

**Fall back to the real browser** - for what headless can't do (push / number-matching MFA, passkeys, an unhandled interstitial). With `interactive=True`, if the headless login can't finish, the authorize URL opens in the user's own browser and the code comes back to the library:

```python
res = login(authorize_url, "you@school.ch", "...", interactive=True)
```

Two ways the code returns, chosen by the `redirect_uri`:

- **loopback** (`http://localhost[:port]/...`): a tiny local server catches the redirect itself, like `az login`. A missing port is filled with a free one.
- **paste** (anything else, e.g. Microsoft's `.../nativeclient`): the user copies the final URL from the address bar and pastes it back.

Call it directly, without ever trying headless, with `browser_login()`:

```python
from entrance import browser_login

res = browser_login(authorize_url, code_verifier=verifier, token_url="https://provider.example/token")
print(res["mode"])   # "loopback" or "paste"
```

The browser's cookies stay in the browser, so an interactive run returns no `session_cookies` and writes no cookie file - persist the `code`/tokens instead. (`webbrowser.open` and `input` can be swapped via `open_browser=` / `prompt=`.)

## Return Value

| Key | When | What |
|---|---|---|
| `code` | always | the authorization code |
| `code_verifier` / `state` | always | echoed back for your own exchange |
| `callback_url` | default mode | the `redirect_uri?code=…&state=…`, built not sent |
| `access_token` / `tokens` | when `token_url` is set | the exchanged token response |
| `redirect_url` / `session_state` | when `ms_redirect=True` | the raw Microsoft → provider redirect |
| `mode` | `browser_login` / `interactive` | `"loopback"` or `"paste"` |

## Caveats

- Works only against **managed** Entra tenants (`login.microsoftonline.com`), not third-party federated IdPs (ADFS, Google, etc.).
- **Push / SMS MFA can't be done headless** - only TOTP (authenticator app). Enroll one and pass its Base32 secret, or use `interactive=True` to finish in a browser.
- Microsoft tweaks its login pages; if a flow breaks, the user-agent or a field name is usually the culprit.

## Disclaimer

Entrance is published for **educational and research purposes only** - to document how OAuth2 / OpenID Connect authorization-code + PKCE flows behave when federated through Microsoft Entra, and how a browserless client negotiates them.

Use it only against accounts you own, or with the explicit authorization of the account or tenant owner. You alone are responsible for your use of it and for complying with Microsoft's terms, your identity provider's terms, your institution's acceptable-use policy, and applicable law. Automating logins to accounts you do not own, evading access controls, or circumventing MFA you were not granted is not the intended use. The software is provided "as is", without warranty of any kind, and the author accepts no liability for misuse. Not affiliated with or endorsed by Microsoft.

## License

[MIT](LICENSE) (c) [PianoNic](https://github.com/PianoNic)
