# login()

Point `login()` at any authorize URL that ends up at `login.microsoftonline.com`;
it drives the Microsoft sign-in (password + MFA, no browser) and returns the
authorization `code` - optionally exchanged for tokens.

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

## MFA, two ways

Pass `totp_secret` (Base32 - a fresh code is generated each attempt) **or**
`totp_code` if you already hold a valid 6-digit code:

```python
login(authorize_url, "you@school.ch", "...", totp_secret="JBSWY3DPEHPK3PXP")
login(authorize_url, "you@school.ch", "...", totp_code="123456")  # used as-is
```

Only TOTP (authenticator-app) second factors can be satisfied headlessly. For
push / number-matching / passkeys, use the [browser fallback](browser.md), or
[mint and enroll a TOTP device](totp.md) once.

## Exchange the code for tokens

Pass a `token_url` and it does the OAuth exchange for you:

```python
res = login(authorize_url, "you@school.ch", "...",
            code_verifier=verifier, token_url="https://provider.example/token")
print(res["access_token"])
```

## Just the Microsoft handoff

Stop at the redirect Microsoft issues back to the provider, untouched:

```python
res = login("https://provider.example/", "you@school.ch", "...", ms_redirect=True)
print(res["redirect_url"])   # https://provider.example/?code=...&state=...&session_state=...
```

## Silent reuse

The first call saves `.ms_session.json`; every call after that skips the password:

```python
login(authorize_url, "you@school.ch", "...")   # full login, saves the jar
login(authorize_url)                            # silent - no password, no MFA
```

## Cookies your way - file or inline

`cookies` takes a file path (loaded on entry, written back on exit), an inline
list of cookie dicts, or `None`. Either way the result always carries
`session_cookies`, so you can store them yourself instead of touching disk:

```python
# inline in, inline out - nothing written to disk
res = login(authorize_url, "you@school.ch", "...", cookies=None)
jar = res["session_cookies"]                    # list of {name, value, domain, path}

# later, seed straight from memory (or your own DB/secret store)
res = login(authorize_url, cookies=jar)         # silent, no file involved
```

## Return value

| Key | When | What |
|---|---|---|
| `code` | always | the authorization code |
| `code_verifier` / `state` | always | echoed back for your own exchange |
| `callback_url` | default mode | the `redirect_uri?code=…&state=…`, built not sent |
| `access_token` / `tokens` | when `token_url` is set | the exchanged token response |
| `redirect_url` / `session_state` | when `ms_redirect=True` | the raw Microsoft → provider redirect |
| `mode` | `browser_login` / `interactive` | `"loopback"` or `"paste"` |

## How it works

- **Impersonate Opera, not Chrome.** Entra serves a JavaScript-only "Chrome SSO
  pull" page (un-replayable without a real browser) when it sees a *Google Chrome*
  user-agent. Presenting as **Opera** - a non-Chrome Chromium - gets the plain,
  replayable credential page instead.
- **Real browser fingerprint.** [`curl_cffi`](https://github.com/lexiforest/curl_cffi)
  replays a genuine browser TLS/JA3 fingerprint.
- **Replay the login XHRs by hand** - `GetCredentialType` → `login` → "Stay signed
  in?"; for MFA, `SAS/BeginAuth` + `SAS/EndAuth` with a TOTP code via
  [`pyotp`](https://github.com/pyauth/pyotp).
- **Intercept the code** at the callback redirect - read off the `Location` header,
  never actually delivered.
- **Silent reuse.** The Microsoft session cookie jar is persisted, so the next run
  needs no password (or MFA) until it expires.

## Caveats

- Works only against **managed** Entra tenants (`login.microsoftonline.com`), not
  third-party federated IdPs (ADFS, Google, etc.).
- Microsoft tweaks its login pages; if a flow breaks, the user-agent or a field
  name is usually the culprit.
