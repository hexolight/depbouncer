"""Test helpers. No test touches the real network: FakeNet answers every
request and fails on anything unexpected. No real package is downloaded."""
import datetime as dt
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from depbouncer import net  # noqa: E402

OSV_Q = "https://api.osv.dev/v1/query"
OSV_B = "https://api.osv.dev/v1/querybatch"


def days_ago(n):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeNet:
    def __init__(self):
        self.routes = {}
        self.osv_version = {}   # (name, version) -> vulns
        self.osv_any = {}       # name -> vulns
        self.vulns = {}         # id -> full record
        self.calls = []
        self.osv_down = False

    def __call__(self, url, body):
        self.calls.append((url, body))
        if url == OSV_Q:
            if self.osv_down:
                raise OSError("network down")
            name, ver = body["package"]["name"], body.get("version")
            return {"vulns": self.osv_version.get((name, ver), []) if ver else self.osv_any.get(name, [])}
        if url == OSV_B:
            if self.osv_down:
                raise OSError("network down")
            out = []
            for q in body["queries"]:
                name, ver = q["package"]["name"], q.get("version")
                vs = self.osv_version.get((name, ver), []) if ver else self.osv_any.get(name, [])
                out.append({"vulns": [{"id": v["id"]} for v in vs]})
            return {"results": out}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            vid = url.rsplit("/", 1)[-1]
            return self.vulns.get(vid, {"id": vid, "summary": ""})
        r = self.routes.get(url)
        if r is None:
            raise net.http_error(url, 404)
        if isinstance(r, Exception):
            raise r
        return r() if callable(r) else r

    # ------------------------------------------------------------ builders
    def npm(self, name, versions=("1.0.0",), latest=None, created_days=1000, downloads=10**6, scripts=None,
            repo=True, deprecated=None):
        latest = latest or versions[-1]
        vers = {}
        for v in versions:
            meta = {"name": name, "version": v, "scripts": scripts or {}}
            if repo:
                meta["repository"] = {"url": f"git+https://github.com/x/{name}.git"}
            if deprecated:
                meta["deprecated"] = deprecated
            vers[v] = meta
        self.routes["https://registry.npmjs.org/" + name] = {
            "name": name, "dist-tags": {"latest": latest}, "versions": vers,
            "time": {"created": days_ago(created_days)}}
        self.routes["https://api.npmjs.org/downloads/point/last-week/" + name] = {"downloads": downloads}

    def pypi(self, name, versions=("1.0.0",), created_days=1000, downloads=10**6, sdist_only=False, yanked=()):
        rel = {}
        for v in versions:
            t = "sdist" if sdist_only else "bdist_wheel"
            rel[v] = [{"upload_time_iso_8601": days_ago(created_days), "packagetype": t, "yanked": v in yanked}]
        base = "https://pypi.org/pypi/" + name
        self.routes[base + "/json"] = {"info": {"version": versions[-1]}, "releases": rel}
        for v in versions:
            self.routes[f"{base}/{v}/json"] = {"info": {"project_urls": {"Source": "https://github.com/x/y"}}}
        norm = name.lower().replace("_", "-").replace(".", "-")
        self.routes[f"https://pypistats.org/api/packages/{norm}/recent"] = {"data": {"last_month": downloads}}

    def nuget(self, name, versions=("1.0.0",), created_days=1000, downloads=10**7, verified=True, listed=True):
        low = name.lower()
        self.routes[f"https://api.nuget.org/v3-flatcontainer/{low}/index.json"] = {"versions": list(versions)}
        self.routes[f"https://api.nuget.org/v3/registration5-gz-semver2/{low}/index.json"] = {
            "items": [{"items": [{"catalogEntry": {"published": days_ago(created_days)}}]}]}
        hit = [{"id": name, "projectUrl": "https://github.com/x/y", "verified": verified,
                "totalDownloads": downloads}] if listed else []
        import urllib.parse
        self.routes["https://azuresearch-usnc.nuget.org/query?prerelease=true&semVerLevel=2.0.0&q=packageid:"
                    + urllib.parse.quote(name)] = {"data": hit}


@pytest.fixture
def fake_net():
    f = FakeNet()
    old = net.set_transport(f)
    yield f
    net.set_transport(old)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Each test gets its own data folder and fake user home."""
    monkeypatch.setenv("DEPBOUNCER_HOME", str(tmp_path / "dbhome"))
    monkeypatch.setenv("DEPBOUNCER_USER_HOME", str(tmp_path / "userhome"))
    (tmp_path / "userhome").mkdir()
    # Fail loudly if any test reaches the real network.
    old = net.set_transport(lambda url, body: (_ for _ in ()).throw(AssertionError(f"real network: {url}")))
    yield tmp_path
    net.set_transport(old)


@pytest.fixture
def cfg():
    from depbouncer.config import Config
    c = Config()
    c.transitive = False
    return c


MAL = {"id": "MAL-2025-0001", "summary": "Malicious code in evil (npm)"}
GHSA_MAL = {"id": "GHSA-xxxx-yyyy-zzzz", "summary": "Malicious Package in flatmap-stream"}
ADV = {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Prototype pollution"}


def codes(result):
    return [c for c, _ in result.reasons]


os.environ.setdefault("PYTHONUTF8", "1")
