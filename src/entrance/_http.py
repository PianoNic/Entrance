"""One shared, thread-safe HTTP client for the token endpoint (and for OutNote's Graph calls).

A client per request pays DNS, TCP and TLS every time; a shared one keeps connections alive and
multiplexes over HTTP/2, so repeat calls reuse them. Backed by wreq behind the small surface
entrance and OutNote use. Connecting is bounded by a short timeout with a few retries, so one dead
address cannot stall a call for the full read timeout.
"""

import http.client as _status
import json as _json
import logging
import threading
import time
from datetime import timedelta
from urllib.parse import urlencode

import wreq.blocking as wb
import wreq.exceptions as wx
from wreq import Method
from wreq.redirect import Policy

log = logging.getLogger("entrance.http")

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 30.0
CONNECT_RETRIES = 3
KEEPALIVE_SECONDS = 60
MAX_REDIRECTS = 10
USER_AGENT = "entrance"

# wreq's exceptions share no base class, so `except HTTPError` catches this tuple.
HTTPError = (
    wx.ConnectionError,
    wx.ConnectionResetError,
    wx.ProxyConnectionError,
    wx.TimeoutError,
    wx.TlsError,
    wx.RequestError,
    wx.BodyError,
    wx.DecodingError,
    wx.RedirectError,
    wx.StatusError,
)

_client = None
_lock = threading.Lock()
_FOLLOW, _NOFOLLOW = Policy.limited(MAX_REDIRECTS), Policy.none()


class Headers(dict):
    """Response headers with case-insensitive lookup.

    ponytail: a repeated header keeps its last value - fine for Graph and the token endpoint;
    sign-in cookies go through curl_cffi, not this client."""

    def get(self, key, default=None):
        return super().get(key.lower(), default)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())

    def __contains__(self, key):
        return super().__contains__(key.lower())


class Response:
    __slots__ = ("status_code", "headers", "content")

    def __init__(self, status_code, headers, content):
        self.status_code, self.headers, self.content = status_code, headers, content

    @property
    def reason_phrase(self):
        return _status.responses.get(self.status_code, "")

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        return _json.loads(self.content)


def _headers(raw):
    return Headers((bytes(k).decode("latin1").lower(), bytes(v).decode("latin1")) for k, v in raw)


class Client:
    def __init__(self):
        self._c = wb.Client(
            gzip=True,
            brotli=True,
            deflate=True,
            zstd=True,
            connect_timeout=timedelta(seconds=CONNECT_TIMEOUT),
            pool_idle_timeout=timedelta(seconds=KEEPALIVE_SECONDS),
            redirect=_NOFOLLOW,
        )

    def request(
        self,
        method,
        url,
        content=None,
        data=None,
        headers=None,
        timeout=READ_TIMEOUT,
        follow_redirects=False,
    ):
        h = {"User-Agent": USER_AGENT, **(headers or {})}
        if data is not None:
            content = urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        kw = {
            "headers": h,
            "read_timeout": timedelta(seconds=timeout),
            "redirect": _FOLLOW if follow_redirects else _NOFOLLOW,
        }
        if content:
            kw["body"] = content
        elif method in ("POST", "PUT", "PATCH"):
            # wreq omits Content-Length on an empty body, and login.microsoftonline.com answers 411.
            h.setdefault("Content-Length", "0")
        m = getattr(Method, method)
        for attempt in range(CONNECT_RETRIES + 1):
            try:
                with self._c.request(m, url, **kw) as r:
                    return Response(r.status.as_int(), _headers(r.headers), bytes(r.bytes()))
            except wx.ConnectionError:  # never connected, so no request was sent: safe to retry
                if attempt == CONNECT_RETRIES:
                    raise
        raise AssertionError("unreachable")

    def post(self, url, data=None, **kw):
        return self.request("POST", url, data=data, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def close(self):
        self._c.close()


def client() -> Client:
    """The process-wide client, created on first use."""
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = Client()
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
        except HTTPError as e:
            log.warning(
                "warm-up %s failed after %.0f ms: %s", url, (time.perf_counter() - t0) * 1000, e
            )
