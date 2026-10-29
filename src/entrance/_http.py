"""One shared, thread-safe HTTP client for the token endpoint (and for OutNote's Graph calls).

A client per request pays DNS, TCP and TLS every time; a shared one keeps connections alive
(HTTP/2 when `h2` is installed) so repeat calls reuse them. Connecting is bounded by a short
timeout with a few retries, so one dead address cannot stall a call for the full read timeout.
"""

import logging
import threading
import time

import httpx

log = logging.getLogger("entrance.http")

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 30.0
CONNECT_RETRIES = 3

_client: httpx.Client | None = None
_lock = threading.Lock()


def _http2() -> bool:
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


def client() -> httpx.Client:
    """The process-wide client, created on first use."""
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = httpx.Client(
                    timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
                    limits=httpx.Limits(
                        max_connections=100, max_keepalive_connections=20, keepalive_expiry=60
                    ),
                    transport=httpx.HTTPTransport(retries=CONNECT_RETRIES, http2=_http2()),
                    follow_redirects=False,
                )
    return _client


def close() -> None:
    """Close and forget the shared client (the next call builds a new one)."""
    global _client
    with _lock:
        c, _client = _client, None
    if c is not None:
        c.close()


def warm_up(urls: list[str]) -> None:
    """Open (and keep alive) a connection to each URL's host; failures are logged, never raised."""
    for url in urls:
        t0 = time.perf_counter()
        try:
            client().head(url)
            log.debug("warm-up %s ok in %.0f ms", url, (time.perf_counter() - t0) * 1000)
        except httpx.HTTPError as e:
            log.warning(
                "warm-up %s failed after %.0f ms: %s", url, (time.perf_counter() - t0) * 1000, e
            )
