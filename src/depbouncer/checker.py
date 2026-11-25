"""Registry checks. Ported from the package-guard skill's check_package.py.

Every check and threshold of the original is kept (and covered by tests);
added: version ranges, look-alike names, sub-dependencies, TR/EN reasons.
Exit codes of the CLI stay 0 PASS, 1 ASK, 2 BLOCK.
"""
import datetime as dt
import re
import time
import urllib.parse
from dataclasses import dataclass, field

from . import net, typo, versions
from .config import Config

OSV_NAME = {"npm": "npm", "pypi": "PyPI", "nuget": "NuGet"}
NAME = re.compile(r"^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
SPEC_CHARS = re.compile(r"^[A-Za-z0-9.+!_\-<>=~^*|, \[\]()]+$")
ORDER = ["PASS", "ASK", "BLOCK"]


@dataclass
class Result:
    verdict: str
    reasons: list = field(default_factory=list)   # [(code, params)]
    facts: list = field(default_factory=list)
    version: str | None = None

    def worst(self, other):
        return ORDER[max(ORDER.index(self.verdict), ORDER.index(other))]


class VersionNotFound(LookupError):
    pass


class RangeUnresolved(LookupError):
    pass


def age_days(stamp):
    t = dt.datetime.fromisoformat(stamp[:19]).replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - t).days


def _npm(name, spec):
    d = net.fetch("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    tags = d.get("dist-tags", {})
    vers = d.get("versions", {})
    if not spec:
        ver = tags.get("latest")
    elif spec in tags:
        ver = tags[spec]
    elif spec in vers:
        ver = spec
    elif versions.sem_parse(spec):
        raise VersionNotFound(spec)
    else:
        ver = versions.npm_resolve(spec, list(vers))
        if ver is None:
            raise RangeUnresolved(spec)
    if ver not in vers:
        raise VersionNotFound(str(ver))
    meta = vers[ver]
    info = {"version": ver, "created": d.get("time", {}).get("created"), "repo": meta.get("repository"),
            "block": [], "ask": []}
    if "-security" in ver:
        info["block"].append(("security_placeholder", {}))
    if any(k in (meta.get("scripts") or {}) for k in ("preinstall", "install", "postinstall")):
        info["ask"].append(("install_script", {}))
    if meta.get("deprecated"):
        info["ask"].append(("deprecated", {}))
    info["downloads"] = lambda: net.fetch("https://api.npmjs.org/downloads/point/last-week/" + name)["downloads"]
    return info


def _pypi(name, spec):
    base = "https://pypi.org/pypi/" + name
    d = net.fetch(base + "/json")
    rel = d.get("releases", {})
    spec = (spec or "").strip()
    if not spec:
        ver = d["info"]["version"]
    elif spec.startswith("==") and "," not in spec and "*" not in spec:
        ver = spec[2:].strip()
    else:
        live = [v for v, fs in rel.items() if fs and not all(f.get("yanked") for f in fs)]
        ver = versions.pypi_resolve(spec, live)
        if ver is None:
            raise RangeUnresolved(spec)
    files = rel.get(ver)
    if not files:
        raise VersionNotFound(ver)
    stamps = [f["upload_time_iso_8601"] for fs in rel.values() for f in fs]
    meta = net.fetch(f"{base}/{urllib.parse.quote(ver)}/json")["info"]
    info = {"version": ver, "created": min(stamps) if stamps else None,
            "repo": meta.get("project_urls") or meta.get("home_page"), "block": [], "ask": []}
    if all(f.get("yanked") for f in files):
        info["ask"].append(("yanked", {}))
    if all(f.get("packagetype") == "sdist" for f in files):
        info["ask"].append(("sdist_only", {}))
    norm = re.sub(r"[-_.]+", "-", name).lower()
    info["downloads"] = lambda: net.fetch(f"https://pypistats.org/api/packages/{norm}/recent")["data"]["last_month"]
    return info


def _nuget(name, spec):
    low = name.lower()
    vers = net.fetch(f"https://api.nuget.org/v3-flatcontainer/{low}/index.json")["versions"]
    stable = [v for v in vers if "-" not in v]
    spec = (spec or "").strip().lower()
    if not spec:
        ver = (stable or vers)[-1].lower()
    elif spec in vers:
        ver = spec
    else:
        ver = versions.nuget_resolve(spec, vers)
        if ver is None:
            raise RangeUnresolved(spec)
    if ver not in vers:
        raise VersionNotFound(ver)
    stamps = []
    for page in net.fetch(f"https://api.nuget.org/v3/registration5-gz-semver2/{low}/index.json")["items"]:
        items = page.get("items") or net.fetch(page["@id"])["items"]
        stamps = [i["catalogEntry"].get("published", "") for i in items]
        stamps = [s for s in stamps if s > "2000"]  # unlisted entries are dated 1900
        if stamps:
            break
    hits = net.fetch("https://azuresearch-usnc.nuget.org/query?prerelease=true&semVerLevel=2.0.0&q=packageid:"
                     + urllib.parse.quote(name))["data"]
    hit = hits[0] if hits else {}
    info = {"version": ver, "created": min(stamps) if stamps else None, "repo": hit.get("projectUrl"),
            "block": [], "ask": []}
    if not hit:
        info["ask"].append(("nuget_unlisted", {}))
    elif not hit.get("verified"):
        info["ask"].append(("nuget_unverified", {}))
    info["downloads"] = lambda: hit["totalDownloads"]
    return info


REGISTRY = {"npm": _npm, "pypi": _pypi, "nuget": _nuget}


def is_malware(v):
    return not v.get("withdrawn") and (
        any(i.startswith("MAL-") for i in [v.get("id", ""), *v.get("aliases", [])])
        or bool(re.search(r"\bmalware\b|^malicious (code|package)", v.get("summary", "") or "", re.I)))


def osv_query(eco, name, version=None):
    q = {"package": {"name": name, "ecosystem": OSV_NAME[eco]}}
    if version:
        q["version"] = version
    return net.fetch("https://api.osv.dev/v1/query", q).get("vulns", [])


def check(eco, name, spec, cfg: Config | None = None, deadline=None, transitive_fn=None):
    cfg = cfg or Config()
    if not NAME.match(name) or (spec and not SPEC_CHARS.match(spec)):
        return Result("ASK", [("bad_name", {})])
    try:
        info = REGISTRY[eco](name, spec)
    except net.HTTPError as e:
        if e.code == 404:
            return Result("BLOCK", [("not_found", {})])
        return Result("ASK", [("http_error", {"code": e.code})])
    except VersionNotFound as e:
        # Removed versions are often removed BECAUSE they were malware: ask OSV anyway.
        try:
            mal = [v["id"] for v in osv_query(eco, name, str(e)) if is_malware(v)]
        except Exception:  # noqa: BLE001
            mal = []
        if mal:
            return Result("BLOCK", [("known_malware", {"ids": ", ".join(mal)}), ("version_not_found", {})])
        return Result("ASK", [("version_not_found", {})])
    except RangeUnresolved as e:
        return Result("ASK", [("range_unresolved", {"spec": str(e)})])
    except Exception as e:  # noqa: BLE001 - anything unexpected is ASK, never PASS
        return Result("ASK", [("verify_error", {"err": str(e)[:200]})])
    block, ask = info["block"], info["ask"]
    facts = [("fact_version", {"v": info["version"]})]
    try:
        here = osv_query(eco, name, info["version"])
        ever = osv_query(eco, name)
        mal_here = [v["id"] for v in here if is_malware(v)]
        mal_ever = [v["id"] for v in ever if is_malware(v)]
        if mal_here:
            block.append(("known_malware", {"ids": ", ".join(mal_here)}))
        elif mal_ever:
            ask.append(("malware_other_versions", {"ids": ", ".join(mal_ever[:5])}))
        others = len(here) - len(mal_here)
        if others:
            ask.append(("advisories", {"n": others}))
    except Exception as e:  # noqa: BLE001
        ask.append(("osv_unreachable", {"err": str(e)[:200]}))
    if info["created"]:
        days = age_days(info["created"])
        facts.append(("fact_age", {"days": days}))
        if days < cfg.min_age_days:
            ask.append(("new_package", {"days": cfg.min_age_days}))
    else:
        ask.append(("date_unknown", {}))
    n = None
    try:
        n = info["downloads"]()
        facts.append(("fact_downloads", {"n": n}))
        if n < cfg.min_downloads[eco]:
            ask.append(("few_downloads", {"n": n}))
    except Exception as e:  # noqa: BLE001
        ask.append(("downloads_unavailable", {"err": str(e)[:120]}))
    if not info["repo"]:
        ask.append(("no_repo", {}))
    target = typo.lookalike(eco, name)
    if target and (n is None or n < typo.SUSPECT_MAX_DOWNLOADS[eco]):
        ask.append(("typosquat", {"target": target}))
    if not block and cfg.transitive and transitive_fn is not None:
        if deadline is not None and deadline - time.monotonic() < 15:
            facts.append(("fact_transitive_skipped", {"why": "time budget"}))
        else:
            tb, ta, tf = transitive_fn(eco, name, info["version"], cfg, deadline)
            block += tb
            ask += ta
            facts += tf
    verdict = "BLOCK" if block else "ASK" if ask else "PASS"
    return Result(verdict, block + ask, facts, info["version"])
