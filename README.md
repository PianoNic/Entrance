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

---

## What is Entrance?

Plenty of services hand you an OAuth "open this URL in a browser to log in" link and federate the actual authentication to **Microsoft Entra**. `entrance` walks that flow for you over pure HTTP - no Playwright, no headless Chromium, no Selenium - and hands back the authorization `code` (or exchanged tokens). Point it at any authorize URL that ends up at `login.microsoftonline.com` and it logs in, handles MFA, and returns.

The whole thing is one small module and two dependencies.

## Features

- 🚪 **No browser** - pure HTTP, drives `login.microsoftonline.com` directly
- 🌐 **Provider-agnostic** - give it any OAuth2 authorize URL federated to Entra
- 🔐 **Headless MFA** - TOTP second factor solved automatically from your authenticator secret
- 🔢 **Number-matching push** - `push_login()` drives an Authenticator push headlessly and streams out the two-digit number to tap, so your own UI can show "tap 42"
- 🙋 **Browser fallback** - `interactive=True` opens the real browser for what headless can't do (passkeys, an unhandled challenge), catching the code via a localhost server or copy-paste
- 🔑 **Mint & enroll TOTP** - `new_totp()` generates a software token, `enroll_totp()` registers a brand-new one on the account, so every later login is fully headless
- 🔢 **Device code sign-in** - `device_login()` / `foci_login(device=True)`: show a short code, the user enters it at a URL - no redirect, no loopback, no copy-paste
- 🧩 **FOCI broker** - `foci_login()` turns one sign-in into tokens for any pre-consented first-party client / scope, persisted for password-free reruns
- 🍪 **Silent SSO** - persisted cookie jar means password-free reruns
- 📦 **Tiny** - one core module, `curl_cffi` + `pyotp`

## Install

```bash
pip install ms-entrance        # or: uv add ms-entrance
```

The import name is `entrance` (`from entrance import login`). Python 3.10+;
`curl_cffi` and `pyotp` are pulled in automatically.

## Quickstart

```python
from entrance import login

res = login(
    "https://provider.example/authorize?client_id=...&state=...&code_challenge=...",
    username="you@school.ch",
    password="...",
    totp_secret="JBSWY3DPEHPK3PXP",   # optional - only if the account has TOTP MFA
)
print(res["code"])           # the authorization code (intercepted at the callback)
print(res["callback_url"])   # the full callback URL - built, NOT sent
```

## Docs

- [`login()`](docs/login.md) - MFA, token exchange, `ms_redirect`, cookies, return value, how it works
- [Number-matching push](docs/push.md) - `push_login()`: capture the tap number server-side for your own UI
- [Browser fallback](docs/browser.md) - `interactive=True` / `browser_login()` (loopback + paste)
- [TOTP devices](docs/totp.md) - `new_totp()` and headless `enroll_totp()`
- [FOCI broker](docs/foci.md) - `foci_login()` / `Broker` for Microsoft first-party clients

## Disclaimer

Entrance is published for **educational and research purposes only** - to document how OAuth2 / OpenID Connect authorization-code + PKCE flows behave when federated through Microsoft Entra, and how a browserless client negotiates them.

Use it only against accounts you own, or with the explicit authorization of the account or tenant owner. You alone are responsible for your use of it and for complying with Microsoft's terms, your identity provider's terms, your institution's acceptable-use policy, and applicable law. Automating logins to accounts you do not own, evading access controls, or circumventing MFA you were not granted is not the intended use. The software is provided "as is", without warranty of any kind, and the author accepts no liability for misuse. Not affiliated with or endorsed by Microsoft.

## License

[MIT](LICENSE) (c) [PianoNic](https://github.com/PianoNic)
