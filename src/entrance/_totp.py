"""Software TOTP tokens: mint a secret, build its `otpauth://` provisioning
URI, and compute / verify codes - so you can create a TOTP "device" up front
and feed its secret back to `login(totp_secret=...)` for fully headless MFA.

Generating and using a secret is entirely local and offline (thin layer over
`pyotp`). **Registering** that secret as an MFA method on an Entra account is a
separate, account-side step: Microsoft gates self-service auth-method
management behind an approved portal app plus a fresh interactive MFA, which
the borrowed first-party clients can't satisfy. Do that part in the **Security
info** portal (<https://aka.ms/mysecurityinfo> -> Add -> Authenticator app ->
"I want to use a different authenticator app") - the `secret` / `uri` here are
exactly what it asks for.
"""

from dataclasses import dataclass

import pyotp

_ISSUER = "Microsoft"


@dataclass
class TotpDevice:
    """A software TOTP token. `secret` is the Base32 seed to keep; `uri` is the
    `otpauth://` provisioning string (render it as a QR to enroll it in an
    authenticator app, or paste the secret into the Security info portal)."""

    secret: str
    account_name: str
    issuer: str = _ISSUER
    digits: int = 6
    period: int = 30

    @property
    def _totp(self):
        return pyotp.TOTP(self.secret, digits=self.digits, interval=self.period)

    @property
    def uri(self):
        return self._totp.provisioning_uri(name=self.account_name, issuer_name=self.issuer)

    def now(self):
        """The current 6-digit code."""
        return self._totp.now()

    def verify(self, code, window=1):
        """True if `code` is valid now (± `window` periods)."""
        return self._totp.verify(str(code).strip(), valid_window=window)

    def as_dict(self):
        return {
            "secret": self.secret,
            "uri": self.uri,
            "account_name": self.account_name,
            "issuer": self.issuer,
            "digits": self.digits,
            "period": self.period,
        }


def new_totp(account_name, issuer=_ISSUER, secret=None, digits=6, period=30):
    """A new `TotpDevice`. A random Base32 `secret` is generated unless you pass
    your own. `account_name` is what shows in the authenticator (e.g. the UPN).

    The secret is usable immediately for codes; to make it a real second factor
    on an Entra account, enroll `device.uri`/`device.secret` once in the
    Security info portal (see the module docstring)."""
    return TotpDevice(
        secret=(secret or pyotp.random_base32()).upper().replace(" ", ""),
        account_name=account_name,
        issuer=issuer,
        digits=digits,
        period=period,
    )


def totp_now(secret, digits=6, period=30):
    """The current code for a Base32 `secret`."""
    return pyotp.TOTP(secret, digits=digits, interval=period).now()


def totp_verify(secret, code, window=1, digits=6, period=30):
    """True if `code` matches `secret` now (± `window` periods)."""
    return pyotp.TOTP(secret, digits=digits, interval=period).verify(
        str(code).strip(), valid_window=window
    )
