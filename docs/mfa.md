# Interactive MFA (`mfa=`)

`mfa=<MfaPrompt>` lets a caller decide the second factor **at the moment Microsoft
asks for it**: approve a number-matching push in Authenticator, or type a code from
an authenticator app. No MFA requested means the sign-in completes straight after
the password and the prompt is never called.

It works on `login()`, `foci_login()` and `push_login()`.

```python
import entrance
from entrance import MfaPrompt, MfaSwitch, Secret

class Prompt(MfaPrompt):
    def choose(self, methods):          # ["push", "otp"], only what the account offers
        return "push" if "push" in methods else "otp"

    def on_push(self, event):           # PushEvent: number_matching / pending / approved ...
        if event.state == entrance.NUMBER_MATCHING:
            print("Tap", event.number, "in Authenticator")

    def otp(self, attempt):             # blocks until the user has a code; attempt is 1..3
        return input("Code: ")

broker = entrance.foci_login("you@school.ch", Secret("password"), mfa=Prompt(), frt_store=None, cookies=None)
```

## The hook

| Method | Called | Notes |
|---|---|---|
| `choose(methods) -> str` | when MFA is required, and again after a switch / retry | `methods` is a list of `"push"` / `"otp"`, only those in the account's `arrUserProofs`, push first |
| `otp(attempt) -> str` | to get an authenticator code (`PhoneAppOTP`) | blocks; `attempt` is 1-based, at most 3 per `choose`; Microsoft rejecting a code asks again |
| `on_push(event)` | for each `PushEvent` of a push | the number, pending polls, then approved/denied/timed_out |
| `should_switch() -> bool` | between push polls | true abandons the push and returns to `choose` |
| `cancelled() -> bool` | between steps and polls | true raises `MfaCancelled` |
| `retry(error) -> bool` | after a denied/timed-out push or spent codes | true returns to `choose` instead of raising |

Raise `MfaSwitch` from `otp()` to abandon the code prompt and go back to `choose`,
and `MfaCancelled` from any callback to stop. Subclass `MfaPrompt` (every method has
a default) or pass any object with the methods you need. `push_timeout` and
`push_interval` bound and pace the push poll. `mfa` takes precedence over
`totp_secret` / `totp_code` and cannot be combined with `push=True`.

## Exceptions

All sign-in failures other than push/cancel derive from `entrance.LoginFailed`.

| Exception | Meaning |
|---|---|
| `InvalidCredentials` | wrong password or unknown account (AADSTS50126, 50034, 50056, 50064) |
| `Unsupported` | cannot be driven headlessly; base of the next two |
| `FederatedAccount` | federated to another IdP (ADFS, Okta ...); `.redirect_url` |
| `UnsupportedMfa` | MFA required but no push/code method (also an `MfaRequired`); `.offered` |
| `Blocked` | refused by policy: Conditional Access (AADSTS53000-53004, 530003 ...), locked or disabled account; `.code` |
| `PushError` | push denied or timed out; `.state` is `denied` / `timed_out` |
| `OtpRejected` | three codes rejected (also an `MfaRequired`); `.attempts` |
| `MfaCancelled` | the caller cancelled |

Federation is detected from `GetCredentialType` (`FederationRedirectUrl`) and from a
post-password redirect to an ADFS-style endpoint. Conditional Access is detected from
the AADSTS code in the page's `sErrorCode` or in an OAuth `error_description`.

## The password

`password` is used once, in memory, to post the sign-in form. It is not stored,
cached or logged, and no exception message or debug dump contains it. Pass a
`Secret("...")` to also drop the reference: `Secret.take()` returns the value once
and forgets it, and the form is built from it only at the moment of submission.
(Python strings cannot be wiped; this drops references, nothing more.)
