"""Sub-dependency checks. Nothing is installed and no install code runs:
- npm: `npm install --package-lock-only --ignore-scripts` in an empty temp folder
- PyPI: `pip install --dry-run --only-binary=:all:` (wheels only, never builds)
- NuGet: walks the registry's dependency groups (lowest matching version)
All resolved names are then checked against OSV in one batch.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

from . import net, versions
from .checker import OSV_NAME, is_malware

MAX_PACKAGES = 1500


def osv_batch(eco, pkgs, cfg):
    """pkgs: iterable of (name, version). Returns (malware list, advisory count)."""
    pkgs = [(n, v) for n, v in pkgs if not cfg.is_private(eco, n)]
    mal, other = [], []
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        body = {"queries": [{"package": {"name": n, "ecosystem": OSV_NAME[eco]}, "version": v} for n, v in chunk]}
        res = net.fetch("https://api.osv.dev/v1/querybatch", body).get("results", [])
        if len(res) != len(chunk):
            raise RuntimeError("OSV batch answer incomplete")
        for (n, v), r in zip(chunk, res):
            for vuln in r.get("vulns", []) or []:
                vid = vuln.get("id", "")
                if vid.startswith("MAL-"):
                    mal.append(f"{n}@{v} ({vid})")
                else:
                    other.append((n, v, vid))
    # The batch API returns ids only; GHSA malware records need their summary.
    # Look up a bounded number of them; the rest count as plain advisories.
    adv = 0
    for idx, (n, v, vid) in enumerate(other):
        if idx < 40 and is_malware(net.fetch("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid))):
            mal.append(f"{n}@{v} ({vid})")
        else:
            adv += 1
    return mal, adv


def _clean_env():
    env = {k: v for k, v in os.environ.items()
           if not k.lower().startswith(("npm_config_", "pip_", "uv_", "yarn_", "nuget_"))}
    return env


def _run(cmd, cwd, timeout):
    return subprocess.run(cmd, cwd=cwd, env=_clean_env(), capture_output=True, text=True,
                          timeout=timeout, stdin=subprocess.DEVNULL,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def npm_tree(name, version, timeout):
    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("npm not found")
    with tempfile.TemporaryDirectory(prefix="depbouncer-") as tmp:
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "depbouncer-probe", "version": "0.0.0", "private": True,
                       "dependencies": {name: version}}, f)
        empty_rc = os.path.join(tmp, ".npmrc-empty")
        open(empty_rc, "w").close()
        r = _run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                  "--registry=https://registry.npmjs.org/", f"--userconfig={empty_rc}"], tmp, timeout)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).strip()[-200:] or f"npm exit {r.returncode}")
        with open(os.path.join(tmp, "package-lock.json"), encoding="utf-8") as f:
            lock = json.load(f)
    out = set()
    for key, meta in (lock.get("packages") or {}).items():
        if not key or not meta.get("version"):
            continue
        n = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        if meta.get("link"):
            continue
        out.add((n, meta["version"]))
    out.discard((name, version))
    return sorted(out)


def pip_tree(name, version, timeout):
    with tempfile.TemporaryDirectory(prefix="depbouncer-") as tmp:
        report = os.path.join(tmp, "report.json")
        r = _run([sys.executable, "-I", "-m", "pip", "install", "--dry-run", "--ignore-installed",
                  "--only-binary=:all:", "--isolated", "--disable-pip-version-check", "--quiet",
                  "--index-url", "https://pypi.org/simple", "--report", report, f"{name}=={version}"],
                 tmp, timeout)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).strip()[-200:] or f"pip exit {r.returncode}")
        with open(report, encoding="utf-8") as f:
            data = json.load(f)
    out = set()
    for item in data.get("install", []):
        md = item.get("metadata", {})
        if md.get("name") and md.get("version"):
            out.add((md["name"], md["version"]))
    out = {(n, v) for n, v in out if n.lower().replace("_", "-") != name.lower().replace("_", "-")}
    return sorted(out)


def _nuget_deps(n, v):
    leaf = net.fetch(f"https://api.nuget.org/v3/registration5-gz-semver2/{n}/{v}.json")
    entry = leaf.get("catalogEntry")
    if isinstance(entry, str):
        entry = net.fetch(entry)
    deps = {}
    for group in (entry or {}).get("dependencyGroups", []) or []:
        for dep in group.get("dependencies", []) or []:
            did = dep.get("id", "").lower()
            if did and did not in deps:
                deps[did] = dep.get("range", "")
    return deps


def _nuget_pick(did, rng):
    vs = net.fetch(f"https://api.nuget.org/v3-flatcontainer/{did}/index.json")["versions"]
    return did, versions.nuget_resolve(rng or "0.0.0", vs)


def nuget_tree(name, version, deadline, max_depth=3):
    """Breadth-first, one version per package id (the union of all target
    frameworks), fetched in parallel with a hard cap."""
    from concurrent.futures import ThreadPoolExecutor
    root = (name.lower(), version.lower())
    resolved = {root[0]: root[1]}
    level = [root]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(max_depth):
            if deadline and time.monotonic() > deadline - 10:
                raise RuntimeError("time budget")
            wanted = {}
            for deps in pool.map(lambda nv: _nuget_deps(*nv), level):
                for did, rng in deps.items():
                    if did not in resolved and did not in wanted:
                        wanted[did] = rng
            if not wanted:
                break
            if len(resolved) + len(wanted) > MAX_PACKAGES:
                raise RuntimeError("dependency graph too large")
            level = []
            for did, rv in pool.map(lambda kv: _nuget_pick(*kv), wanted.items()):
                if rv:
                    resolved[did] = rv
                    level.append((did, rv))
    return [(n, v) for n, v in resolved.items() if (n, v) != root]


def check(eco, name, version, cfg, deadline):
    """Returns (block_reasons, ask_reasons, facts)."""
    budget = 60.0 if deadline is None else max(5.0, min(60.0, deadline - time.monotonic() - 10))
    try:
        if eco == "npm":
            pkgs = npm_tree(name, version, budget)
        elif eco == "pypi":
            pkgs = pip_tree(name, version, budget)
        else:
            pkgs = nuget_tree(name, version, deadline)
        if not pkgs:
            return [], [], [("fact_transitive", {"n": 0})]
        if len(pkgs) > MAX_PACKAGES:
            return [], [("too_many", {"n": len(pkgs)})], []
        mal, adv = osv_batch(eco, pkgs, cfg)
    except Exception as e:  # noqa: BLE001 - uncertain result is never PASS
        return [], [("transitive_failed", {"err": str(e)[:200]})], []
    facts = [("fact_transitive", {"n": len(pkgs)})]
    if adv:
        facts.append(("fact_transitive_adv", {"n": adv}))
    if mal:
        return [("transitive_malware", {"items": ", ".join(mal[:5])})], [], facts
    return [], [], facts
