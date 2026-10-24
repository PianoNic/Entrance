# Browser fallback

For what headless can't do - push / number-matching MFA, passkeys, an unhandled
interstitial - finish the sign-in in the user's own browser and get the code back.

With `interactive=True`, if the headless `login()` can't finish, the authorize URL
opens in the browser and the code comes back to the library:

```python
res = login(authorize_url, "you@school.ch", "...", interactive=True)
```

### Normal (full manual) login

To skip headless entirely and have the user do the **whole** sign-in in the browser
- email, password and 2FA - pass `interactive="always"` (no credentials needed):

```python
res = login(authorize_url, interactive="always")   # opens the full Microsoft login page
```

With plain `interactive=True` and no `username`/`password`, `login()` also lands
here after a quick silent-cookie check. `browser_login(authorize_url)` is the same
thing called directly. This works through the higher-level helpers too - e.g.
`foci_login(interactive="always")` or `outnote.authenticate(interactive="always")`
pop a full browser login and return a ready client.

Two ways the code returns, chosen by the `redirect_uri`:

- **loopback** (`http://localhost[:port]/...`): a tiny local server catches the
  redirect itself, like `az login`. A missing port is filled with a free one.
- **paste** (anything else, e.g. Microsoft's `.../nativeclient`): the user copies
  the final URL from the address bar and pastes it back.

Call it directly, without ever trying headless, with `browser_login()`:

```python
from entrance import browser_login

res = browser_login(authorize_url, code_verifier=verifier,
                    token_url="https://provider.example/token")
print(res["mode"])   # "loopback" or "paste"
```

The browser's cookies stay in the browser, so an interactive run returns no
`session_cookies` and writes no cookie file - persist the `code` / tokens instead.
`webbrowser.open` and `input` can be swapped via `open_browser=` / `prompt=`.
