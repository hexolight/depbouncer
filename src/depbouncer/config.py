"""Settings, data folder and the private-package exclusion list."""
import fnmatch
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = """\
# depbouncer settings / ayarlar
# lang: "tr", "en" or "both"
lang = "both"

# "auto": use the agent's own approval prompt where it really works, otherwise deny.
# "deny": always deny and ask the user to run `depbouncer approve`.
ask_mode = "auto"

# Check sub-dependencies (npm lockfile, pip dry-run, NuGet dependency graph).
transitive = true

# Private packages: never sent to any outside service.
# Shell-style patterns, e.g. "@mycorp/*", "mycorp-*", "MyCorp.*"
[private]
npm = []
pypi = []
nuget = []
# What to answer for private packages: "ask" or "pass"
result = "ask"

[thresholds]
min_age_days = 90
min_downloads_npm = 1000     # weekly
min_downloads_pypi = 1000    # monthly
min_downloads_nuget = 5000   # total
"""


def data_dir() -> Path:
    env = os.environ.get("DEPBOUNCER_HOME")
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA") or os.path.join(Path.home(), ".local", "share")
    return Path(base) / "depbouncer"


@dataclass
class Config:
    lang: str = "both"
    ask_mode: str = "auto"
    transitive: bool = True
    private: dict = field(default_factory=lambda: {"npm": [], "pypi": [], "nuget": []})
    private_result: str = "ask"
    min_age_days: int = 90
    min_downloads: dict = field(default_factory=lambda: {"npm": 1000, "pypi": 1000, "nuget": 5000})

    def is_private(self, eco, name):
        pats = self.private.get(eco, [])
        n = name.lower()
        if eco == "pypi":
            n = re.sub(r"[-_.]+", "-", n)
        for p in pats:
            p = p.lower()
            if eco == "pypi":
                p = re.sub(r"[-_.]+", "-", p)
            if fnmatch.fnmatchcase(n, p):
                return True
        return False


def load() -> Config:
    cfg = Config()
    path = data_dir() / "config.toml"
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return cfg
    # A broken config must not silently weaken the guard: keep defaults.
    except (OSError, tomllib.TOMLDecodeError):
        return cfg
    if raw.get("lang") in ("tr", "en", "both"):
        cfg.lang = raw["lang"]
    if raw.get("ask_mode") in ("auto", "deny"):
        cfg.ask_mode = raw["ask_mode"]
    if isinstance(raw.get("transitive"), bool):
        cfg.transitive = raw["transitive"]
    priv = raw.get("private", {})
    for eco in ("npm", "pypi", "nuget"):
        v = priv.get(eco, [])
        if isinstance(v, list):
            cfg.private[eco] = [str(x) for x in v]
    if priv.get("result") in ("ask", "pass"):
        cfg.private_result = priv["result"]
    th = raw.get("thresholds", {})
    # Thresholds can only be made stricter than the defaults, never weaker.
    if isinstance(th.get("min_age_days"), int):
        cfg.min_age_days = max(cfg.min_age_days, th["min_age_days"])
    for eco in ("npm", "pypi", "nuget"):
        v = th.get(f"min_downloads_{eco}")
        if isinstance(v, int):
            cfg.min_downloads[eco] = max(cfg.min_downloads[eco], v)
    return cfg


def write_json_atomic(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
