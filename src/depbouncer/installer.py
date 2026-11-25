"""Install / uninstall: copies the app, registers global hooks and the
/pc-scan skill in each agent, backs up every file before changing it, and
merges instead of overwriting. Uninstall removes only entries carrying the
depbouncer marker."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .config import DEFAULT_CONFIG, data_dir, read_json, write_json_atomic

MARKER = "depbouncer-hook"
SKILL_MARKER = "<!-- depbouncer:pc-scan -->"
HOOK_TIMEOUT = 120


def home():
    return Path(os.environ.get("DEPBOUNCER_USER_HOME") or Path.home())


def agent_files():
    h = home()
    return {
        "claude": h / ".claude" / "settings.json",
        "codex": h / ".codex" / "hooks.json",
        "cursor": h / ".cursor" / "hooks.json",
        "antigravity": h / ".gemini" / "config" / "hooks.json",
    }


def skill_dirs():
    h = home()
    return {
        "claude": h / ".claude" / "skills" / "pc-scan",
        "codex": h / ".agents" / "skills" / "pc-scan",        # Codex user scope; Cursor reads it too
        "cursor": h / ".agents" / "skills" / "pc-scan",
        "antigravity": h / ".gemini" / "config" / "skills" / "pc-scan",
    }


def detect():
    h = home()
    found = []
    if (h / ".claude").is_dir():
        found.append("claude")
    if (h / ".codex").is_dir():
        found.append("codex")
    if (h / ".cursor").is_dir():
        found.append("cursor")
    if (h / ".gemini" / "antigravity").is_dir() or (h / ".gemini" / "config").is_dir() or \
            (h / ".gemini" / "bin" / "agy.exe").exists():
        found.append("antigravity")
    return found


def real_python():
    exe = sys.executable
    if not exe or "windowsapps" in exe.lower():
        raise RuntimeError("Need a real Python 3.11+ (the Microsoft Store 'python' alias is not usable). "
                           "Install from python.org or run install.ps1, which finds it with the py launcher.")
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11+ required")
    return exe


# ------------------------------------------------------------ command lines
def hook_cmd_path():
    return data_dir() / "bin" / "depbouncer-hook.cmd"


def hook_command(agent):
    p = str(hook_cmd_path())
    fwd = p.replace("\\", "/")
    if agent == "claude":           # Git Bash (or PowerShell without Git Bash)
        return f'"{fwd}" claude' if " " in fwd else f"{fwd} claude"
    if agent == "cursor":           # PowerShell on Windows
        return f"& '{p}' cursor" if " " in p else f"{fwd} cursor"
    return f"& '{p}' {agent}" if " " in p else f"{fwd} {agent}"


def write_launchers(py, app):
    bin_dir = data_dir() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = app / "launcher.py"
    enc = "oem" if os.name == "nt" else "utf-8"     # cmd.exe reads .cmd files in the OEM code page
    # If Python itself cannot run (missing, 9009, crash before output), the
    # launcher still blocks: exit 2 for Claude Code / Cursor, a JSON deny for
    # Codex / Antigravity (their Python path always exits 0 with JSON).
    reason = "depbouncer could not run: failing safe"
    (bin_dir / "depbouncer-hook.cmd").write_text(
        "@echo off\r\n"
        f'"{py}" -I "{launcher}" hook %1\r\n'
        "if not errorlevel 1 exit /b 0\r\n"
        'if /i "%~1"=="codex" (\r\n'
        '  echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
        f'"permissionDecisionReason":"{reason}"}}}}\r\n'
        "  exit /b 0\r\n)\r\n"
        'if /i "%~1"=="antigravity" (\r\n'
        f'  echo {{"decision":"deny","reason":"{reason}"}}\r\n'
        "  exit /b 0\r\n)\r\n"
        "exit /b 2\r\n", encoding=enc)
    (bin_dir / "depbouncer.cmd").write_text(
        "@echo off\r\n"
        f'"{py}" -I "{launcher}" %*\r\n', encoding=enc)


# ------------------------------------------------------------------ merging
def _load(path):
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8-sig")
    if not text.strip():
        return {}
    data = json.loads(text)          # raises on invalid JSON: we never overwrite what we cannot read
    if not isinstance(data, dict):
        raise ValueError("top level is not an object")
    return data


def _strip_ours(groups):
    out = []
    for g in groups or []:
        if not isinstance(g, dict):
            out.append(g)
            continue
        if MARKER in json.dumps(g):
            inner = g.get("hooks")
            if isinstance(inner, list) and "command" not in g:
                kept = [h for h in inner if MARKER not in json.dumps(h)]
                if kept:
                    out.append({**g, "hooks": kept})
            continue
        out.append(g)
    return out


def merge(agent, data, remove=False):
    data = dict(data)
    if agent in ("claude", "codex"):
        hooks = dict(data.get("hooks") or {})
        pre = _strip_ours(hooks.get("PreToolUse"))
        if not remove:
            entry = {"type": "command", "command": hook_command(agent), "timeout": HOOK_TIMEOUT}
            if agent == "claude":
                entry["onFailure"] = "block"   # Claude Code 2.1.295+: failure = block
                matcher = "Bash|PowerShell|Write|Edit|MultiEdit"
            else:
                matcher = "Bash|apply_patch|Edit|Write"
            pre.append({"matcher": matcher, "hooks": [entry]})
        if pre:
            hooks["PreToolUse"] = pre
        else:
            hooks.pop("PreToolUse", None)
        if hooks:
            data["hooks"] = hooks
        else:
            data.pop("hooks", None)
        return data
    if agent == "cursor":
        data.setdefault("version", 1)
        hooks = dict(data.get("hooks") or {})
        for ev in ("beforeShellExecution", "preToolUse"):
            lst = [h for h in (hooks.get(ev) or []) if MARKER not in json.dumps(h)]
            if not remove:
                lst.append({"command": hook_command("cursor"), "timeout": HOOK_TIMEOUT, "failClosed": True})
            if lst:
                hooks[ev] = lst
            else:
                hooks.pop(ev, None)
        data["hooks"] = hooks
        return data
    if agent == "antigravity":
        data.pop("depbouncer", None)
        if not remove:
            data["depbouncer"] = {"PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": hook_command("antigravity"), "timeout": HOOK_TIMEOUT}]}]}
        return data
    raise ValueError(agent)


def backup(path, stamp):
    if not path.exists():
        return None
    dest = data_dir() / "backups" / stamp / f"{path.parent.name}-{path.name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    return dest


# -------------------------------------------------------------------- skill
def skill_text(agent):
    cli = str(data_dir() / "bin" / "depbouncer.cmd")
    report = str(data_dir() / "scan" / "report.md")
    extra = "disable-model-invocation: true\n" if agent == "claude" else ""
    return f"""---
name: pc-scan
description: Read-only scan of this whole PC for installed packages with known malware (npm, PyPI, NuGet) using OSV. Run only when the user asks for /pc-scan.
{extra}---
{SKILL_MARKER}
# /pc-scan (depbouncer)

Run the depbouncer scanner. It is read-only, runs at low priority, goes one
folder at a time, saves progress and continues where it stopped. It never
opens browser profiles, .env files, keys or cookies and does not use Windows
Defender.

1. Start or continue the scan in the background (it can take hours):
   `"{cli}" scan`
2. Check progress whenever the user asks: `"{cli}" scan --status`
3. When it finishes, read `{report}` and summarise for the user in their
   language: findings with evidence (OSV id, package, version, file path),
   how likely each is a false alarm and why, and the list of places that were
   not scanned.

Do not delete, move, uninstall or "fix" anything yourself. Only report.
"""


def install_skill(agent, dry_run, state):
    d = skill_dirs()[agent]
    f = d / "SKILL.md"
    if f.exists() and SKILL_MARKER not in f.read_text(encoding="utf-8", errors="replace"):
        return f"skip: {f} exists and is not ours"
    if not dry_run:
        d.mkdir(parents=True, exist_ok=True)
        f.write_text(skill_text(agent), encoding="utf-8")
        state.setdefault("skills", [])
        if str(d) not in state["skills"]:
            state["skills"].append(str(d))
    return f"skill: {f}"


# --------------------------------------------------------------------- PATH
def _user_path(add=None, remove=None):
    if os.name != "nt":
        return False
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
        try:
            cur, typ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            cur, typ = "", winreg.REG_EXPAND_SZ
        parts = [p for p in cur.split(";") if p]
        low = [p.lower().rstrip("\\") for p in parts]
        changed = False
        if add and add.lower().rstrip("\\") not in low:
            parts.append(add)
            changed = True
        if remove:
            keep = [p for p in parts if p.lower().rstrip("\\") != remove.lower().rstrip("\\")]
            changed = changed or len(keep) != len(parts)
            parts = keep
        if changed:
            winreg.SetValueEx(k, "Path", 0, typ, ";".join(parts))
            ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 2000, None)
    return changed


# ------------------------------------------------------------------ install
def copy_app(dry_run):
    src = Path(__file__).resolve().parent.parent       # .../src
    app = data_dir() / "app"
    if app.exists() and src == app.resolve():
        return app
    if not dry_run:
        if app.exists():
            shutil.rmtree(app)
        shutil.copytree(src / "depbouncer", app / "depbouncer",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(src / "launcher.py", app / "launcher.py")
    return app


def install(agents=None, dry_run=False, add_path=True, out=print):
    py = real_python()
    agents = agents or detect()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    state = read_json(data_dir() / "install-state.json", {})
    out(f"depbouncer install {'(dry run / deneme) ' if dry_run else ''}-> {data_dir()}")
    out(f"python: {py}")
    app = copy_app(dry_run)
    if not dry_run:
        write_launchers(py, app)
        cfg = data_dir() / "config.toml"
        if not cfg.exists():
            cfg.write_text(DEFAULT_CONFIG, encoding="utf-8")
    errors = 0
    for agent in agents:
        path = agent_files()[agent]
        try:
            data = _load(path)
        except (ValueError, OSError) as e:
            out(f"[{agent}] HATA/ERROR: {path} okunamadı/could not be read ({e}); dokunulmadı/left unchanged")
            errors += 1
            continue
        new = merge(agent, data)
        out(f"[{agent}] hook -> {path}")
        if not dry_run:
            b = backup(path, stamp)
            if b:
                out(f"[{agent}] yedek/backup -> {b}")
            write_json_atomic(path, new)
            state.setdefault("agents", [])
            if agent not in state["agents"]:
                state["agents"].append(agent)
        out(f"[{agent}] " + install_skill(agent, dry_run, state))
    if add_path and not dry_run:
        if _user_path(add=str(data_dir() / "bin")):
            out(f"PATH += {data_dir() / 'bin'} (yeni terminal açın / open a new terminal)")
        state["path"] = str(data_dir() / "bin")
    if not dry_run:
        state["installed"] = stamp
        write_json_atomic(data_dir() / "install-state.json", state)
    if "codex" in agents:
        out("[codex] ÖNEMLİ/IMPORTANT: Codex'te /hooks açıp depbouncer hook'una güvenin (trust); "
            "aksi halde çalışmaz. / In Codex open /hooks and trust the depbouncer hook, otherwise it will not run.")
    if "cursor" in agents or "antigravity" in agents:
        out("Cursor/Antigravity: ayarları yeniden yüklemek için uygulamayı yeniden başlatın / restart the app.")
    return 1 if errors else 0


def uninstall(dry_run=False, purge=False, out=print):
    stamp = time.strftime("%Y%m%d-%H%M%S") + "-uninstall"
    state = read_json(data_dir() / "install-state.json", {})
    for agent, path in agent_files().items():
        if not path.exists():
            continue
        try:
            data = _load(path)
        except (ValueError, OSError) as e:
            out(f"[{agent}] HATA/ERROR: {path} okunamadı ({e}); dokunulmadı")
            continue
        if MARKER not in json.dumps(data) and "depbouncer" not in data:
            continue
        new = merge(agent, data, remove=True)
        out(f"[{agent}] hook kaldırıldı/removed <- {path}")
        if not dry_run:
            backup(path, stamp)
            write_json_atomic(path, new)
    for d in set(skill_dirs().values()):
        f = d / "SKILL.md"
        if f.exists() and SKILL_MARKER in f.read_text(encoding="utf-8", errors="replace"):
            out(f"skill kaldırıldı/removed <- {d}")
            if not dry_run:
                shutil.rmtree(d)
    if not dry_run:
        try:
            _user_path(remove=str(data_dir() / "bin"))
        except OSError:
            pass
        for sub in ("bin",):
            shutil.rmtree(data_dir() / sub, ignore_errors=True)
        if purge:
            for name in ("config.toml", "cache.json", "approvals.json", "pending.json", "log.jsonl",
                         "install-state.json"):
                try:
                    (data_dir() / name).unlink()
                except OSError:
                    pass
            shutil.rmtree(data_dir() / "scan", ignore_errors=True)
    out("Yedekler korunur / backups are kept: " + str(data_dir() / "backups"))
    return 0


# ------------------------------------------------------------------- doctor
def doctor(out=print):
    ok = True
    try:
        out("python: " + real_python())
    except RuntimeError as e:
        out(f"FAIL python: {e}")
        ok = False
    hook = hook_cmd_path()
    out(f"{'ok  ' if hook.exists() else 'FAIL'} {hook}")
    ok &= hook.exists()
    for agent, path in agent_files().items():
        try:
            present = MARKER in json.dumps(_load(path)) or "depbouncer" in _load(path)
        except (ValueError, OSError):
            present = False
        out(f"{'ok  ' if present else '--  '} {agent}: {path}")
    if hook.exists():
        samples = {
            "claude": ({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo hi"},
                        "permission_mode": "default"}, 0),
            "cursor": ({"hook_event_name": "beforeShellExecution", "command": "echo hi"}, 0),
            "antigravity": ({"toolCall": {"name": "run_command", "args": {"CommandLine": "echo hi"}}}, 0),
            "codex": ({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo hi"}}, 0),
        }
        for agent, (payload, want) in samples.items():
            r = subprocess.run(["cmd", "/d", "/c", str(hook), agent], input=json.dumps(payload),
                               capture_output=True, text=True, timeout=60)
            bad = subprocess.run(["cmd", "/d", "/c", str(hook), agent], input="not json",
                                 capture_output=True, text=True, timeout=60)
            if agent in ("codex", "antigravity"):
                blocked = bad.returncode == 0 and '"deny"' in bad.stdout
            else:
                blocked = bad.returncode == 2
            good = r.returncode == want and '"deny"' not in r.stdout and blocked
            ok &= good
            out(f"{'ok  ' if good else 'FAIL'} hook {agent}: normal={r.returncode} garbage-blocked={blocked}")
    try:
        from . import scan
        scan.selftest()
        out("ok   OSV self-test (flatmap-stream detected as malware)")
    except Exception as e:  # noqa: BLE001
        out(f"FAIL OSV self-test: {e}")
        ok = False
    return 0 if ok else 1
