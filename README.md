# <p align="center">Entrance</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/PianoNic/Entrance/main/assets/entrance-icon.svg" width="150" alt="Entrance Logo">
</p>
<p align="center">
  <strong>Your headless entrance to Microsoft Entra.</strong><br>
  Browser-grade OAuth login for any Microsoft-federated provider — without a browser.
</p>
<p align="center">
  <a href="https://github.com/PianoNic/Entrance"><img src="https://badgetrack.pianonic.ch/badge?tag=entrance&label=visits&color=0078D4&style=flat" alt="visits"/></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-0078D4" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/browser-not%20required-0078D4" alt="No browser"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-0078D4" alt="MIT license"/></a>
</p>

> [!WARNING]
> For automating logins to **your own accounts** and other **authorized** use (your tooling, your tenant, education). It drives a real sign-in with real credentials — treat the cookie jar and any tokens like passwords. Not affiliated with or endorsed by Microsoft.

## About The Project

Plenty of services hand you an OAuth "open this URL in a browser to log in" link and federate the actual authentication to **Microsoft Entra**. `entrance` walks that flow for you over pure HTTP — no Playwright, no headless Chromium, no Selenium — and hands back the authorization `code` (or exchanged tokens). Point it at any authorize URL that ends up at `login.microsoftonline.com` and it logs in, handles MFA, and returns.

The whole thing is one file (`entrance.py`) and two dependencies.

## How It Works

The trick that makes browserless login actually work against a modern Entra tenant:

- **Impersonate Opera, not Chrome.** Entra serves a JavaScript-only "Chrome SSO pull" page (un-replayable without a real browser) when it sees a *Google Chrome* user-agent. Tell it you're **Opera** — a non-Chrome Chromium — and it serves the plain credential page instead, which *is* replayable.
- **Real browser fingerprint.** [`curl_cffi`](https://github.com/lexiforest/curl_cffi) replays a genuine browser TLS/JA3 fingerprint, so Entra's edge sees a browser at the wire level.
- **Replay the login XHRs by hand** — `GetCredentialType` → `login` → "Stay signed in?". For MFA, the `SAS/BeginAuth` + `SAS/EndAuth` pair with a **TOTP** code computed via [`pyotp`](https://github.com/pyauth/pyotp).
- **Intercept the code** at the callback redirect — it's read off the `Location` header and never actually delivered.
- **Silent reuse.** The Microsoft session cookie jar is persisted, so the next run logs in with no password (and no MFA prompt) until it expires.

## Features

- 🚪 **No browser** — pure HTTP, drives `login.microsoftonline.com` directly
- 🌐 **Provider-agnostic** — give it any OAuth2 authorize URL federated to Entra
- 🔐 **Headless MFA** — TOTP second factor solved automatically from your authenticator secret
- 🍪 **Silent SSO** — persisted cookie jar means password-free reruns
- 🎛️ **Three return modes** — the raw `code`, exchanged `access_token`, or just the Microsoft redirect
- 📦 **Tiny** — one module, `curl_cffi` + `pyotp`

## Installation

```bash
pip install curl_cffi pyotp
```

Then drop [`entrance.py`](./entrance.py) into your project. Requires Python 3.10+.

## Quickstart

```python
from entrance import login

# Intercept the authorization code from any Entra-federated authorize URL
res = login(
    "https://provider.example/authorize?client_id=...&state=...&code_challenge=...",
    username="you@school.ch",
    password="...",
    totp_secret="JBSWY3DPEHPK3PXP",   # optional — only if the account has TOTP MFA
)

print(res["code"])           # the authorization code (intercepted at the callback)
print(res["callback_url"])   # the full callback URL — built, NOT sent
```

**Exchange the code for tokens** — pass a `token_url` and it does the OAuth exchange for you:

```python
res = login(authorize_url, "you@school.ch", "...",
            code_verifier=verifier, token_url="https://provider.example/token")
print(res["access_token"])
```

**Just the Microsoft handoff** — stop at the redirect Microsoft issues back to the provider, untouched:

```python
res = login("https://provider.example/", "you@school.ch", "...", ms_redirect=True)
print(res["redirect_url"])   # https://provider.example/?code=...&state=...&session_state=...
```

**Silent reuse** — the first call saves `.ms_session.json`; every call after that skips the password:

```python
login(authorize_url, "you@school.ch", "...")   # full login, saves the jar
login(authorize_url)                            # silent — no password, no MFA
```

## Return Value

| Key | When | What |
|---|---|---|
| `code` | always | the authorization code |
| `code_verifier` / `state` | always | echoed back for your own exchange |
| `callback_url` | default mode | the `redirect_uri?code=…&state=…`, built not sent |
| `access_token` / `tokens` | when `token_url` is set | the exchanged token response |
| `redirect_url` / `session_state` | when `ms_redirect=True` | the raw Microsoft → provider redirect |

## Caveats

- Works only against **managed** Entra tenants (`login.microsoftonline.com`), not third-party federated IdPs (ADFS, Google, etc.).
- **Push / SMS MFA can't be done headless** — only TOTP (authenticator app). Enroll one and pass its Base32 secret.
- Microsoft tweaks its login pages; if a flow breaks, the user-agent or a field name is usually the culprit.

## License

[MIT](LICENSE) © [PianoNic](https://github.com/PianoNic)
