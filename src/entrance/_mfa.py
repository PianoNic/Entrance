"""Interactive second-factor hook for the headless password sign-in.

Pass an `MfaPrompt` as `mfa=` to `entrance.login` / `foci_login` / `push_login`
and Entrance asks it, only when Microsoft actually requests MFA, which of the
methods the account offers to use, then drives that method:

  * `"push"` - Authenticator number-matching approval (`PhoneAppNotification`).
  * `"otp"`  - a code from an authenticator app (`PhoneAppOTP`), up to
    `OTP_ATTEMPTS` tries.

Everything here is plain Python and thread-friendly: the sign-in blocks inside
the prompt callbacks, so a web service can run it on a worker thread and answer
the user from another.
"""

PUSH = "push"
OTP = "otp"
OTP_ATTEMPTS = 3


class MfaSwitch(Exception):
    """Raised (by `MfaPrompt.otp`, or by Entrance when `should_switch()` is true
    during a push) to abandon the current method and go back to `choose`."""


class MfaCancelled(RuntimeError):
    """The caller cancelled the sign-in (`MfaPrompt.cancelled()` returned true,
    or a prompt callback raised it)."""


class MfaPrompt:
    """Base class for the `mfa=` hook. Override what you need; every method has a
    safe default, so a duck-typed object with only some of them also works.

    All callbacks run on the thread that called the sign-in and may block.
    """

    def choose(self, methods):
        """Pick the second factor. `methods` lists only what the account offers,
        normalized to `"push"` / `"otp"` (push first). Return one of them. Called
        again after a switch, a denied/timed-out push or exhausted code attempts
        (when `retry` allowed it). Raise `MfaCancelled` to give up."""
        return methods[0]

    def otp(self, attempt):
        """Block until the user has a code and return it (`attempt` is 1-based,
        at most `OTP_ATTEMPTS`). Raise `MfaSwitch` to pick another method or
        `MfaCancelled` to stop."""
        raise MfaCancelled("no authenticator code source")

    def on_push(self, event):
        """Receive each `PushEvent` of a push (number, pending, approved, ...)."""

    def should_switch(self):
        """Polled between push polls; return true to abandon the push and go back
        to `choose`."""
        return False

    def cancelled(self):
        """Polled between steps; return true to abort with `MfaCancelled`."""
        return False

    def retry(self, error):
        """A push was denied/timed out (`PushError`) or the code attempts ran out
        (`OtpRejected`). Return true to go back to `choose` instead of raising."""
        return False


def hook(mfa, name):
    """`mfa.<name>` or the `MfaPrompt` default, so duck-typed prompts work."""
    fn = getattr(mfa, name, None)
    return fn if callable(fn) else getattr(MfaPrompt, name).__get__(mfa)


class Secret:
    """A one-shot holder for a password: `take()` returns it once and forgets it,
    so the only live reference is the one used to submit it to Microsoft. Pass a
    `Secret` wherever a `password` is accepted; the repr never shows the value.
    (Python strings are immutable and can't be wiped; this drops references.)"""

    __slots__ = ("_v",)

    def __init__(self, value):
        self._v = value

    def take(self):
        v, self._v = self._v, None
        return v

    def __bool__(self):
        return self._v is not None

    def __repr__(self):
        return "Secret(<hidden>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Secret can't be pickled")
