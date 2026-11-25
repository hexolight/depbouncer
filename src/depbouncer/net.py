"""The only module that talks to the network.

Every request goes to a fixed list of public hosts and carries only package
names and versions. Tests replace the transport with `set_transport`.
"""
import gzip
import json
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "api.npmjs.org",
    "pypi.org",
    "pypistats.org",
    "api.nuget.org",
    "azuresearch-usnc.nuget.org",
    "api.osv.dev",
}
USER_AGENT = f"depbouncer/{__version__}"
TIMEOUT = 10

HTTPError = urllib.error.HTTPError


class BlockedHost(Exception):
    pass


def _real_transport(url, body):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 (host allow-listed)
        raw = r.read()
    return json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)


_transport = _real_transport


def set_transport(fn):
    """Replace the transport (tests). Returns the previous one."""
    global _transport
    old, _transport = _transport, fn
    return old


def fetch(url, body=None):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise BlockedHost(url)
    return _transport(url, body)


def http_error(url, code):
    """Build an HTTPError (used by fake transports in tests)."""
    return urllib.error.HTTPError(url, code, "error", {}, None)
