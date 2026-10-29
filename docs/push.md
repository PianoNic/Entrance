# Number-matching push

Microsoft Authenticator **number matching** is the default second factor on most
tenants: after the password, Microsoft sends a push and shows a two-digit number
that the user taps in the app. `push_login()` drives that headlessly and hands
you the number as it happens, so your own UI can show "Open Authenticator and
tap 42" - no Microsoft page, no browser.

```python
from entrance import push_login, NUMBER_MATCHING

def on_event(ev):
    if ev.state == NUMBER_MATCHING:
        print(ev.message)      # "Open Microsoft Authenticator and tap 42 to approve."
        print(ev.number)       # "42"

broker = push_login("you@school.ch", "password", on_event=on_event)
graph_token = broker("d3590ed6-52b3-4102-aeff-aad2292ab01c")   # Office client -> Graph
```

`push_login()` returns a [`Broker`](foci.md) once the user approves, exactly like
`foci_login()`. `foci_login(push=True, on_push=...)` and `login(push=True,
on_push=...)` expose the same capability at their own layers.

## The event stream

`on_event` receives a `PushEvent` as the sign-in progresses:

| `state` | When | Fields |
|---|---|---|
| `number_matching` | the number is known (right after the push is sent) | `number` (e.g. `"42"`), `message`, `expires_in` (seconds) |
| `pending` | once per poll while waiting | `message` |
| `approved` | the user tapped the number | `message` |
| `denied` | the user rejected the prompt | `message` (the Microsoft result) |
| `timed_out` | no response before `timeout` | `message` |

The state constants are importable: `from entrance import NUMBER_MATCHING,
PENDING, APPROVED, DENIED, TIMED_OUT`. On `denied` / `timed_out` the call raises
`PushError` (its `.state` is the terminal state); any other failure raises
`entrance.MfaRequired` (e.g. the account has no push method - only TOTP).

```python
from entrance import push_login, PushError

try:
    broker = push_login(user, pw, on_event=on_event, timeout=120, interval=3)
except PushError as e:
    print(e.state)   # "denied" or "timed_out"
```

`timeout` (default 120 s) bounds the wait; `interval` (default 3 s) paces the
poll. `cookies` and `frt_store` default to `None` (nothing is written to disk),
which suits a stateless server; pass paths to reuse a session or persist the
refresh token.

## Why this flow, and not device code

Number matching surfaces its number only where a *credential* sign-in reaches
the Entra MFA step. Entrance drives that step over HTTP (`SAS/BeginAuth` +
`SAS/EndAuth`); for `AuthMethodId=PhoneAppNotification` the `BeginAuth` response
carries an `Entropy` integer - the number - and `EndAuth` is polled until the
user approves. That is the only place the number exists server-side.

The OAuth 2.0 **device-code** flow (`device_login()`) does *not* expose it: its
`/devicecode` response returns only the device `user_code`, and the token poll
just returns `authorization_pending` until the user finishes on Microsoft's own
page - where Microsoft, not Entrance, shows any number-matching prompt. Use
device code when you *want* Microsoft to host the sign-in; use `push_login()`
when you want to show the number on your own screen.

## Running a web "link your account" screen

For a browser flow where your frontend collects the password and renders the
number, run `push_login()` on the server in a background thread and let the
`on_event` callback publish state that a poll endpoint reads:

```python
# start: kick off the sign-in, remember the latest event per session
state = {}  # session_id -> {"status": ..., "number": ..., "refresh_token": ...}

def run(session_id, user, pw):
    def on_event(ev):
        state[session_id] = {"status": ev.state, "number": ev.number, "message": ev.message}
    try:
        broker = push_login(user, pw, on_event=on_event)
        state[session_id] = {"status": "approved", "refresh_token": broker.refresh_token}
    except Exception as e:  # PushError / MfaRequired / LoginFailed
        state[session_id] = {"status": "error", "message": str(e)}

# the frontend polls a /status endpoint that returns state[session_id]:
#   number_matching -> render "tap {number}"
#   pending         -> keep polling
#   approved        -> store refresh_token, done
#   denied/timed_out/error -> show the message
```

Treat the refresh token and any cookie jar like passwords; never log the number
alongside the credentials.
