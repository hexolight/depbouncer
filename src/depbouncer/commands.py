"""Find package installs inside a shell command line (bash, PowerShell, cmd)."""
import base64
import os
import re
from dataclasses import dataclass


@dataclass
class Intent:
    eco: str | None = None
    name: str | None = None
    spec: str | None = None
    problem: tuple | None = None      # (code, params): ASK without any network call
    origin: str = ""
    bare: str | None = None           # "npm" / "pypi" / "nuget": install from the manifest in cwd
    req_file: str | None = None       # pip -r file


INSTALL_HINT = re.compile(
    r"\b(?:(?:npm|pnpm|yarn|bun)(?:\.cmd|\.exe)?\s+(?:i|in|install|add|isntall|ci|dlx|x|create|init|"
    r"update|up|upgrade)\b|npx\b|pnpx\b|bunx\b|uvx\b|pipx\s|pip[0-9.]*(?:\.exe)?\s+(?:install|download)\b|"
    r"-m\s+pip\b|uv\s+(?:add|pip|tool|sync|run\s+--with)\b|dotnet\s+(?:add|package|tool\s+install|restore)\b|"
    r"nuget(?:\.exe)?\s+install\b|Install-Package\b)", re.I)

_SEPARATORS = {"&&", "||", ";", "|", "&", "\n"}


def tokenize(s):
    """Split into words and separators. Quotes are removed; backslashes are kept
    (Windows paths). Good enough for agent-written commands; anything odd ends
    up as ASK through the INSTALL_HINT cross-check."""
    out, cur, quote, has = [], [], None, False
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "`" and quote == '"' and i + 1 < len(s):
                i += 1
                cur.append(s[i])
            else:
                cur.append(c)
            i += 1
            continue
        if c in "'\"":
            quote, has = c, True
            i += 1
            continue
        two = s[i:i + 2]
        if two in ("&&", "||"):
            if cur or has:
                out.append("".join(cur))
            cur, has = [], False
            out.append(two)
            i += 2
            continue
        if c in ";|&\n\r":
            if cur or has:
                out.append("".join(cur))
            cur, has = [], False
            out.append("\n" if c in "\r\n" else c)
            i += 1
            continue
        if c.isspace():
            if cur or has:
                out.append("".join(cur))
            cur, has = [], False
            i += 1
            continue
        cur.append(c)
        has = True
        i += 1
    if cur or has:
        out.append("".join(cur))
    return out


def segments(s):
    seg, out = [], []
    toks = tokenize(s)
    for idx, t in enumerate(toks):
        if t in _SEPARATORS:
            # PowerShell call operator: "& 'C:\x\npm.cmd' install a" -> keep going
            if t == "&" and not seg:
                continue
            if seg:
                out.append(seg)
            seg = []
        else:
            seg.append(t)
    if seg:
        out.append(seg)
    return out


def exe(tok):
    b = re.split(r"[\\/]", tok)[-1].lower()
    for suf in (".exe", ".cmd", ".bat", ".ps1"):
        if b.endswith(suf):
            b = b[: -len(suf)]
    if re.fullmatch(r"python[0-9.]*w?|py", b):
        return "python"
    if re.fullmatch(r"pip[0-9.]*", b):
        return "pip"
    return b


def _positional(args, value_flags, stop_at_dashdash=True):
    """Split args into (positionals, flags dict). Flags given as --x=v or --x v."""
    pos, flags, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a == "--" and stop_at_dashdash:
            pos += args[i + 1:]
            break
        if a.startswith("-") and len(a) > 1:
            if "=" in a:
                k, v = a.split("=", 1)
                flags.setdefault(k, []).append(v)
            elif a in value_flags and i + 1 < len(args):
                flags.setdefault(a, []).append(args[i + 1])
                i += 1
            else:
                flags.setdefault(a, []).append(True)
        else:
            pos.append(a)
        i += 1
    return pos, flags


def _registry_problem(flags, names):
    for n in names:
        if n in flags:
            return ("custom_registry", {"flag": n})
    return None


# ------------------------------------------------------------------ npm family
NPM_VALUE = {"--registry", "--prefix", "--workspace", "-w", "--tag", "--cache", "--userconfig", "--globalconfig",
             "--loglevel", "--omit", "--include", "--install-strategy", "--before", "-p", "--package", "-c",
             "--call", "--filter", "-F", "--dir", "-C", "--cwd", "--network-concurrency", "--save-prefix"}
NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
               "add", "install-test", "it", "a"}
NPM_BARE = {"ci", "clean-install", "ic", "install-clean", "isntall-clean", "update", "up", "upgrade", "udpate"}


_NPM_NON_REGISTRY = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|\.|/|~|"
                               r"[A-Za-z]:[\\/])")


def _npm_non_registry(s):
    return bool(_NPM_NON_REGISTRY.match(s)) or s.endswith((".tgz", ".tar.gz")) or \
        bool(re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s))


def npm_spec(raw, eco="npm"):
    """Turn an npm-style spec into an Intent."""
    s = raw.strip()
    if not s:
        return None
    if _npm_non_registry(s):
        return Intent(problem=("non_registry", {"spec": s}), origin=s)
    m = re.match(r"^(@[^@/\s]+/[^@\s]+|[^@\s]+)(?:@(.*))?$", s)
    if not m:
        return Intent(problem=("bad_name", {}), origin=s)
    name, spec = m.group(1), m.group(2)
    if spec and spec.startswith("npm:"):            # alias@npm:real@1.0
        return npm_spec(spec[4:], eco)
    if spec and spec.startswith("workspace:"):
        return None
    if spec and _npm_non_registry(spec):            # name@github:a/b, name@file:../x
        return Intent(problem=("non_registry", {"spec": s}), origin=s)
    return Intent(eco="npm", name=name, spec=spec or None, origin=s)


def create_pkg(name):
    """npm init foo -> create-foo; @s -> @s/create; @s/x -> @s/create-x."""
    m = re.match(r"^(@[^/@]+)(?:/([^@]+))?(@.*)?$", name)
    if m:
        base = f"{m.group(1)}/create" + (f"-{m.group(2)}" if m.group(2) else "")
        return base + (m.group(3) or "")
    n, _, v = name.partition("@")
    return ("create-" + n) + (("@" + v) if v else "")


def parse_npm(tool, args):
    pos, flags = _positional(args, NPM_VALUE)
    reg = _registry_problem(flags, ["--registry", "--userconfig", "--globalconfig"])
    out = []
    if tool in ("npx", "pnpx", "bunx"):
        pk = [v for k in ("-p", "--package") for v in flags.get(k, []) if v is not True]
        targets = pk or pos[:1]
    else:
        if not pos:
            return [Intent(bare="npm", origin=tool)] if tool in ("yarn",) else []
        sub, rest = pos[0], pos[1:]
        if tool == "yarn" and sub == "global" and rest:
            sub, rest = rest[0], rest[1:]
        if sub in ("dlx", "x", "exec") and tool in ("pnpm", "yarn", "bun", "npm"):
            pk = [v for k in ("-p", "--package") for v in flags.get(k, []) if v is not True]
            if tool == "pnpm" and sub == "exec":
                return []
            if tool == "npm" and sub in ("exec", "x"):
                targets = pk or rest[:1]
            elif tool == "yarn" and sub == "exec":
                return []
            elif tool == "bun" and sub == "exec":
                return []
            else:
                targets = pk or rest[:1]
        elif sub in ("create", "init") and rest:
            targets = [create_pkg(rest[0])]
        elif sub in NPM_INSTALL or (tool in ("pnpm", "yarn", "bun") and sub in ("update", "up", "upgrade")):
            if not rest:
                return [Intent(bare="npm", origin=f"{tool} {sub}", problem=reg)]
            targets = rest
        elif sub in NPM_BARE:
            return [Intent(bare="npm", origin=f"{tool} {sub}", problem=reg)]
        else:
            return []
    for t in targets:
        it = npm_spec(t)
        if it:
            if reg:
                it.problem = reg
            out.append(it)
    return out


# ---------------------------------------------------------------- pip family
PIP_VALUE = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
             "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--platform",
             "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "--progress-bar",
             "--log", "--proxy", "--retries", "--timeout", "--cache-dir", "--report", "-d", "--dest",
             "--trusted-host", "--python", "-p", "--group", "--optional", "--package", "--with", "--from",
             "--index", "--default-index", "--only-binary", "--no-binary", "--config-settings", "-C",
             "--global-option", "--pre-release", "--prerelease", "--resolution", "--directory", "--project",
             "--extra", "--script", "--with-requirements", "--exclude-newer"}
PIP_REGISTRY = ["-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index",
                "--trusted-host"]
_PEP508 = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def pip_spec(raw):
    s = raw.strip().split(";", 1)[0].strip()   # drop environment markers
    if not s or s.startswith("#"):
        return None
    if re.match(r"^(git\+|hg\+|svn\+|bzr\+|https?:|file:|\.|/|~|[A-Za-z]:\\)", s) or " @ " in s or \
            s.endswith((".whl", ".tar.gz", ".zip")):
        return Intent(problem=("non_registry", {"spec": s}), origin=s)
    m = _PEP508.match(s)
    if not m:
        return Intent(problem=("bad_name", {}), origin=s)
    name, spec = m.group(1), m.group(3).strip().replace(" ", "")
    if spec.startswith("@"):
        return Intent(problem=("non_registry", {"spec": s}), origin=s)
    if spec and not re.match(r"^(===|==|!=|~=|>=|<=|>|<)", spec):
        return Intent(problem=("bad_name", {}), origin=s)
    return Intent(eco="pypi", name=name, spec=spec or None, origin=s)


def parse_pip(args, cwd, allow_bare=False):
    pos, flags = _positional(args, PIP_VALUE)
    reg = _registry_problem(flags, PIP_REGISTRY)
    out = []
    for f in flags.get("-r", []) + flags.get("--requirement", []) + flags.get("--with-requirements", []):
        if f is not True:
            out.append(Intent(req_file=os.path.join(cwd or "", f), origin=f"-r {f}", problem=reg))
    for e in flags.get("-e", []) + flags.get("--editable", []):
        out.append(Intent(problem=("non_registry", {"spec": f"-e {e}"}), origin=str(e)))
    for p in pos:
        it = pip_spec(p)
        if it:
            if reg:
                it.problem = reg
            out.append(it)
    return out


def parse_python(args, cwd):
    # python [-I -u ...] -m pip install ...  /  py -3 -m pip ...  /  python -m uv ...
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-m":
        i += 1
    if i + 1 < len(args) and args[i] == "-m":
        mod, rest = args[i + 1], args[i + 2:]
        if mod in ("pip", "pip3"):
            return parse_pip_cmd(rest, cwd)
        if mod == "uv":
            return parse_uv(rest, cwd)
        if mod == "pipx":
            return parse_pipx(rest, cwd)
    return []


def parse_pip_cmd(args, cwd):
    pos = [a for a in args if not a.startswith("-")]
    if not pos or pos[0] not in ("install", "download"):
        return []
    return parse_pip(args[args.index(pos[0]) + 1:], cwd)


def parse_uv(args, cwd):
    if not args:
        return []
    sub, rest = args[0], args[1:]
    if sub == "pip" and rest:
        return parse_pip_cmd(rest, cwd)
    if sub == "add":
        res = parse_pip(rest, cwd)
        return res
    if sub in ("sync", "lock"):
        return [Intent(bare="pypi", origin=f"uv {sub}")]
    if sub == "tool" and rest and rest[0] in ("install", "run", "upgrade"):
        return parse_uvx(rest[1:], cwd)
    if sub == "run":
        pos, flags = _positional(rest, PIP_VALUE)
        return [x for w in flags.get("--with", []) if w is not True for x in [pip_spec(w)] if x]
    return []


def parse_uvx(args, cwd):
    pos, flags = _positional(args, PIP_VALUE)
    reg = _registry_problem(flags, PIP_REGISTRY)
    specs = [v for v in flags.get("--from", []) if v is not True] or pos[:1]
    specs += [v for v in flags.get("--with", []) if v is not True]
    out = []
    for s in specs:
        it = pip_spec(s)
        if it:
            if reg:
                it.problem = reg
            out.append(it)
    return out


def parse_pipx(args, cwd):
    if not args:
        return []
    sub, rest = args[0], args[1:]
    if sub in ("install", "run"):
        return parse_uvx(rest, cwd)[:1] if sub == "run" else parse_uvx(rest, cwd)
    if sub == "inject" and len(rest) >= 2:
        return [x for s in rest[1:] if not s.startswith("-") for x in [pip_spec(s)] if x]
    return []


# -------------------------------------------------------------------- NuGet
DOTNET_VALUE = {"-v", "--version", "-s", "--source", "-f", "--framework", "--package-directory", "--project",
                "--add-source", "--configfile", "--tool-path", "-a", "--arch", "--verbosity"}


def parse_dotnet(args):
    if not args:
        return []
    pos, flags = _positional(args, DOTNET_VALUE)
    reg = _registry_problem(flags, ["-s", "--source", "--add-source", "--configfile"])
    ver = next((v for k in ("-v", "--version") for v in flags.get(k, []) if v is not True), None)
    name = None
    if pos[:1] == ["add"] and "package" in pos:
        idx = pos.index("package")
        name = pos[idx + 1] if idx + 1 < len(pos) else None
    elif pos[:2] == ["package", "add"] and len(pos) > 2:
        name = pos[2]
    elif pos[:2] == ["tool", "install"] and len(pos) > 2:
        name = pos[2]
    elif pos[:1] == ["restore"]:
        return [Intent(bare="nuget", origin="dotnet restore", problem=reg)]
    if not name:
        return []
    if "@" in name and not ver:
        name, ver = name.split("@", 1)
    return [Intent(eco="nuget", name=name, spec=ver, origin=name, problem=reg)]


def parse_nuget_exe(args):
    pos, flags = _positional(args, {"-Version", "-Source", "-OutputDirectory", "-ConfigFile"})
    if pos[:1] != ["install"] or len(pos) < 2:
        return []
    reg = _registry_problem(flags, ["-Source", "-ConfigFile"])
    ver = next((v for v in flags.get("-Version", []) if v is not True), None)
    return [Intent(eco="nuget", name=pos[1], spec=ver, origin=pos[1], problem=reg)]


def parse_install_package(args):
    # Visual Studio Package Manager Console: Install-Package Name -Version 1.0
    pos, flags = _positional(args, {"-Version", "-Source", "-ProjectName"})
    if not pos:
        return []
    ver = next((v for v in flags.get("-Version", []) if v is not True), None)
    return [Intent(eco="nuget", name=pos[0], spec=ver, origin=pos[0],
                   problem=_registry_problem(flags, ["-Source"]))]


# ------------------------------------------------------------------ wrappers
_WRAPPERS = {"sudo", "env", "time", "nice", "nohup", "start", "call", "exec", "command", "winpty", "npx.cmd"}


def _unwrap(seg, cwd, depth):
    """Handle cmd /c, powershell -Command, bash -c, env VAR=1 ... Returns intents or None."""
    while seg and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]) or exe(seg[0]) in _WRAPPERS):
        seg = seg[1:]
        while seg and seg[0].startswith("/") and len(seg[0]) == 2:   # start /b
            seg = seg[1:]
    if not seg:
        return []
    tool = exe(seg[0])
    args = seg[1:]
    if tool == "cmd":
        for i, a in enumerate(args):
            if a.lower() in ("/c", "/k", "/s/c"):
                return parse(" ".join(args[i + 1:]), cwd, depth + 1)
        return []
    if tool in ("powershell", "pwsh"):
        for i, a in enumerate(args):
            al = a.lower()
            if al in ("-c", "-command", "-com", "-comm"):
                return parse(" ".join(args[i + 1:]), cwd, depth + 1)
            if al in ("-e", "-ec", "-enc", "-encodedcommand") and i + 1 < len(args):
                try:
                    inner = base64.b64decode(args[i + 1]).decode("utf-16-le")
                except Exception:  # noqa: BLE001
                    return [Intent(problem=("unparsed_install", {}), origin="encoded")]
                return parse(inner, cwd, depth + 1)
        return []
    if tool in ("bash", "sh", "zsh", "dash", "wsl"):
        for i, a in enumerate(args):
            if a in ("-c", "-lc", "-ic", "-ilc", "-cl") or (a.startswith("-") and "c" in a and len(a) <= 4):
                return parse(" ".join(args[i + 1:]), cwd, depth + 1)
        if tool == "wsl" and args:
            return parse(" ".join(a for a in args if a not in ("-e", "--exec", "--")), cwd, depth + 1)
        return []
    return None


def parse_segment(seg, cwd, depth=0):
    if not seg:
        return []
    u = _unwrap(seg, cwd, depth)
    if u is not None:
        return u
    while seg and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]) or exe(seg[0]) in _WRAPPERS):
        seg = seg[1:]
    if not seg:
        return []
    tool, args = exe(seg[0]), seg[1:]
    if tool in ("npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx"):
        return parse_npm(tool, args)
    if tool == "pip":
        return parse_pip_cmd(args, cwd)
    if tool == "python":
        return parse_python(args, cwd)
    if tool == "uv":
        return parse_uv(args, cwd)
    if tool == "uvx":
        return parse_uvx(args, cwd)
    if tool == "pipx":
        return parse_pipx(args, cwd)
    if tool == "dotnet":
        return parse_dotnet(args)
    if tool == "nuget":
        return parse_nuget_exe(args)
    if tool == "install-package":
        return parse_install_package(args)
    return []


def parse(command, cwd=None, depth=0):
    """All install intents in a command line. Anything that looks like an
    install but could not be parsed becomes an ASK intent."""
    if depth > 4:
        return [Intent(problem=("unparsed_install", {}), origin="nested")]
    intents, recognised = [], 0
    for seg in segments(command):
        found = parse_segment(seg, cwd, depth)
        if found or INSTALL_HINT.search(" ".join(seg)):
            recognised += 1 if found else 0
        intents += found
    hints = len(INSTALL_HINT.findall(command))
    if hints and not intents:
        # e.g. Invoke-Expression "npm i x", $c = "pip install y"; & $c
        return [Intent(problem=("unparsed_install", {}), origin=command[:120])]
    if hints > recognised and depth == 0 and _looks_obfuscated(command):
        intents.append(Intent(problem=("unparsed_install", {}), origin=command[:120]))
    return intents


def _looks_obfuscated(command):
    return bool(re.search(r"\b(iex|invoke-expression|eval|\$\(|`|-encodedcommand|frombase64string)", command, re.I))
