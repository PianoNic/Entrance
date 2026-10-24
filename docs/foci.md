# FOCI broker

`foci_login()` signs in against a pre-consented Microsoft first-party client, gets
a **FOCI family refresh token**, and returns a `Broker` that trades it for an
access token for any first-party client / scope on demand - no app registration,
no further sign-ins. The refresh token is persisted (atomically, 0600), so later
runs skip the sign-in entirely.

```python
from entrance import foci_login

broker = foci_login("you@school.ch", "password", totp_secret="BASE32")  # saves .ms_frt
graph_token = broker("d3590ed6-52b3-4102-aeff-aad2292ab01c")            # Office client -> Graph
onenote_token = broker("1fec8e78-bce4-4aaf-ab1b-5451cc387264")          # a different client
auth_api = broker("some-client", "api://resource/.default")             # a non-Graph resource
```

- A live `.ms_frt` means no sign-in at all; a revoked one (`invalid_grant`) is
  dropped and a fresh sign-in runs. `frt_store=None` disables persistence.
- `client_id=` chooses the sign-in client (OfficeHome by default); `interactive=True`
  and every other `login()` kwarg pass through.

Reuse a saved token later, or bring your own, with `Broker` directly:

```python
from entrance import Broker

broker = Broker(refresh_token, store=".ms_frt")
token = broker(client_id)                       # cached per (client_id, scope), rotates the FRT
```

`TokenError` is raised when the token endpoint refuses a grant (`err.error` is the
OAuth code, e.g. `invalid_grant`). `read_secret` / `write_secret` are the atomic
0600 file helpers the store uses.

Which clients are FOCI-family and pre-consented is tenant-dependent. This is the
engine behind [OutNote](https://github.com/PianoNic/OutNote)'s Microsoft 365 access;
see its [clients map](https://github.com/PianoNic/OutNote/blob/main/docs/clients.md)
for a worked example and how to re-probe a tenant.
