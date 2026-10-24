# TOTP devices

Turn a password-plus-push account into a fully headless one: mint a software-TOTP
secret and enroll it as a second factor, then pass it to `login(totp_secret=...)`.

## Mint a device

`new_totp()` generates a software token (or wraps a secret you supply) and gives
you the Base32 `secret` plus an `otpauth://` provisioning URI:

```python
from entrance import new_totp

dev = new_totp("you@school.ch")
print(dev.secret)   # Base32 - store it, pass to login(totp_secret=...)
print(dev.uri)      # otpauth://... - render as a QR, or paste the secret into the portal
print(dev.now())    # the current 6-digit code
print(dev.verify(code))
```

Generating and using the secret is local and offline. There are also module-level
`totp_now(secret)` and `totp_verify(secret, code)` helpers.

## Enroll it automatically

`enroll_totp()` registers a **brand-new** software-TOTP factor on the signed-in
user's own account - driving the same My Sign-Ins / Security info backend the
portal uses (*Add → Authenticator app → "use a different app"*) - and returns the
active device:

```python
from entrance import enroll_totp

dev = enroll_totp("you@school.ch", "password", totp_secret="EXISTING_BASE32")
print(dev.secret)   # a brand-new factor, already active on the account
login(authorize_url, "you@school.ch", "password", totp_secret=dev.secret)  # now fully headless
```

Entra won't let you add a second factor without proving a current one (the
`ngcmfa` "fresh MFA" claim), so you must already hold a working factor - pass an
existing `totp_secret` / `totp_code`, or `interactive=True` to approve it in a
browser.

`enroll_totp` **mutates the account** (it adds a sign-in method; it never touches
existing ones), so use it only on accounts you own or are authorized to change. If
you'd rather do it by hand, enroll the `secret` / `uri` from `new_totp()` once at
[Security info](https://aka.ms/mysecurityinfo).

### How it works

The flow behind `enroll_totp`, reverse-engineered from the live portal:

1. The sign-in carries a `claims` param forcing `ngcmfa` (fresh MFA). The My
   Sign-Ins client is a Single-Page App, so the code is exchanged **cross-origin**
   (an `Origin` header) for the app's own-audience token (`<client>/.default`), not
   a Graph token.
2. `POST /api/session/authorize` → a session context (the `sessionctxv2` header).
3. `POST /api/authenticationmethods/initializemobileapp {securityInfoType:3}` →
   the Base32 `SecretKey`.
4. `POST /api/authenticationmethods/new {Type:3, Data:{secretKey}}` → a
   `VerificationContext`.
5. `POST /api/authenticationmethods/verify {.., VerificationData:<code>}` →
   `VerificationState:2` (active).
