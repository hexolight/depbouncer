"""Dependency files: detect them, read their direct dependencies, and diff
two versions so that only added or changed dependencies are checked."""
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET

from .commands import Intent, npm_spec, pip_spec


def kind(path):
    b = os.path.basename(path).lower()
    if b == "package.json":
        return "package.json"
    if re.fullmatch(r"(requirements|constraints)[\w.-]*\.(txt|in)", b) or b.endswith(".requirements.txt"):
        return "requirements"
    if b == "pyproject.toml":
        return "pyproject"
    if b == "pipfile":
        return "pipfile"
    if b.endswith((".csproj", ".fsproj", ".vbproj")) or b in ("directory.packages.props", "directory.build.props"):
        return "msbuild"
    if b == "packages.config":
        return "packages.config"
    return None


class Unparseable(ValueError):
    pass


def _npm_deps(text):
    try:
        d = json.loads(text) if text.strip() else {}
    except ValueError as e:
        raise Unparseable(str(e)) from e
    out = {}
    if not isinstance(d, dict):
        raise Unparseable("not an object")
    for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (d.get(sec) or {}).items():
            out[("npm", name)] = str(spec)
    for name, spec in (d.get("overrides") or {}).items():
        if isinstance(spec, str):
            out[("npm", name)] = spec
    return out


def _req_lines(text):
    out = {}
    for line in text.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            out[("pypi-include", line)] = line
            continue
        if line.startswith(("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host")):
            out[("pypi-index", line)] = line
            continue
        if line.startswith(("-e", "--editable")):
            out[("pypi-raw", line)] = line
            continue
        if line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        key = re.sub(r"[-_.]+", "-", m.group(1)).lower() if m else line
        out[("pypi", key)] = line
    return out


def _pep_list(items, out):
    for s in items or []:
        if isinstance(s, str):
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", s)
            key = re.sub(r"[-_.]+", "-", m.group(1)).lower() if m else s
            out[("pypi", key)] = s


def _poetry_dict(d, out):
    for name, v in (d or {}).items():
        if name.lower() == "python":
            continue
        if isinstance(v, str):
            out[("pypi", re.sub(r"[-_.]+", "-", name).lower())] = _poetry_to_pep(name, v)
        elif isinstance(v, dict):
            if any(k in v for k in ("git", "path", "url", "source")):
                out[("pypi-raw", name)] = f"{name} @ {json.dumps(v)}"
            else:
                out[("pypi", re.sub(r"[-_.]+", "-", name).lower())] = _poetry_to_pep(name, v.get("version", "*"))


def _poetry_to_pep(name, v):
    v = v.strip()
    if v in ("*", ""):
        return name
    if v[0].isdigit():
        return f"{name}=={v}"
    if v[0] in "^~":
        base = v.lstrip("^~=")
        parts = [int(p) for p in re.findall(r"\d+", base)[:3]]
        if not parts:
            return f"{name}{v}"
        if v[0] == "^":
            i = next((k for k, p in enumerate(parts) if p != 0), len(parts) - 1)
        else:
            i = 1 if len(parts) >= 2 else 0
        upper = parts[:i] + [parts[i] + 1]
        return f"{name}>={base},<{'.'.join(map(str, upper))}"
    return f"{name}{v}"


def _pyproject(text):
    try:
        d = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as e:
        raise Unparseable(str(e)) from e
    out = {}
    proj = d.get("project", {})
    _pep_list(proj.get("dependencies"), out)
    for group in (proj.get("optional-dependencies") or {}).values():
        _pep_list(group, out)
    for group in (d.get("dependency-groups") or {}).values():
        _pep_list([g for g in group if isinstance(g, str)], out)
    tool = d.get("tool", {})
    _pep_list((tool.get("uv") or {}).get("dev-dependencies"), out)
    poetry = tool.get("poetry") or {}
    _poetry_dict(poetry.get("dependencies"), out)
    _poetry_dict(poetry.get("dev-dependencies"), out)
    for g in (poetry.get("group") or {}).values():
        _poetry_dict((g or {}).get("dependencies"), out)
    if (tool.get("uv") or {}).get("index") or (tool.get("uv") or {}).get("sources"):
        out[("pypi-index", "tool.uv")] = json.dumps(tool["uv"].get("index") or tool["uv"].get("sources"))[:120]
    return out


def _pipfile(text):
    try:
        d = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as e:
        raise Unparseable(str(e)) from e
    out = {}
    for sec in ("packages", "dev-packages"):
        for name, v in (d.get(sec) or {}).items():
            if isinstance(v, str):
                out[("pypi", re.sub(r"[-_.]+", "-", name).lower())] = name if v == "*" else f"{name}{v}"
            elif isinstance(v, dict) and any(k in v for k in ("git", "path", "file", "index")):
                out[("pypi-raw", name)] = f"{name} @ {json.dumps(v)}"
            elif isinstance(v, dict):
                ver = v.get("version", "*")
                out[("pypi", re.sub(r"[-_.]+", "-", name).lower())] = name if ver == "*" else f"{name}{ver}"
    for src in d.get("source", []) or []:
        url = src.get("url", "")
        if "pypi.org" not in url:
            out[("pypi-index", url)] = url
    return out


def _msbuild(text):
    if not text.strip():
        return {}
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise Unparseable("DTD not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise Unparseable(str(e)) from e
    out = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("PackageReference", "PackageVersion", "GlobalPackageReference", "package"):
            name = el.get("Include") or el.get("Update") or el.get("id")
            ver = el.get("Version") or el.get("version") or el.get("VersionOverride")
            if ver is None:
                for ch in el:
                    if ch.tag.split("}")[-1] in ("Version", "VersionOverride"):
                        ver = (ch.text or "").strip()
            if name:
                out[("nuget", name.lower())] = f"{name}@{ver or ''}"
        if tag in ("RestoreSources", "RestoreAdditionalProjectSources") and (el.text or "").strip():
            out[("nuget-source", el.text.strip())] = el.text.strip()
    return out


PARSERS = {"package.json": _npm_deps, "requirements": _req_lines, "pyproject": _pyproject,
           "pipfile": _pipfile, "msbuild": _msbuild, "packages.config": _msbuild}


def deps(path, text):
    return PARSERS[kind(path)](text)


def to_intent(key, value):
    eco, name = key
    if eco == "npm":
        if re.match(r"^(workspace:)", value):
            return None
        if value.startswith("npm:"):
            return npm_spec(value[4:])
        it = npm_spec(f"{name}@{value}") if value and value not in ("*", "latest", "") else npm_spec(name)
        return it
    if eco == "pypi":
        return pip_spec(value)
    if eco == "nuget":
        n, _, v = value.partition("@")
        if v and "$(" in v:
            return Intent(problem=("range_unresolved", {"spec": v}), origin=value)
        return Intent(eco="nuget", name=n, spec=v or None, origin=value)
    if eco in ("pypi-include",):
        return Intent(problem=("non_registry", {"spec": value}), origin=value)
    if eco in ("pypi-index", "nuget-source"):
        return Intent(problem=("custom_registry", {"flag": value[:80]}), origin=value)
    if eco == "pypi-raw":
        return pip_spec(value) if not value.startswith("-") else Intent(problem=("non_registry", {"spec": value}),
                                                                       origin=value)
    return None


def diff(path, old_text, new_text):
    """Intents for dependencies that are new or changed in new_text."""
    new = deps(path, new_text)
    try:
        old = deps(path, old_text or "")
    except Unparseable:
        old = {}
    out = []
    for key, val in new.items():
        if old.get(key) == val:
            continue
        it = to_intent(key, val)
        if it:
            out.append(it)
    return out


def all_intents(path, text):
    return [i for k, v in deps(path, text).items() for i in [to_intent(k, v)] if i]


def find_manifests(cwd, eco):
    names = {"npm": ["package.json"], "pypi": ["pyproject.toml", "requirements.txt", "Pipfile"]}.get(eco)
    if eco == "nuget":
        try:
            return [os.path.join(cwd, f) for f in os.listdir(cwd) if kind(f) == "msbuild" or f == "packages.config"]
        except OSError:
            return []
    return [os.path.join(cwd, n) for n in names if os.path.isfile(os.path.join(cwd, n))]
