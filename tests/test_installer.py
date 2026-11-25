"""Install/uninstall run against a fake user home (DEPBOUNCER_USER_HOME)."""
import json
import os
from pathlib import Path

import pytest

from depbouncer import installer


@pytest.fixture
def uhome():
    h = Path(os.environ["DEPBOUNCER_USER_HOME"])
    for d in (".claude", ".codex", ".cursor", ".gemini/config", ".gemini/antigravity"):
        (h / d).mkdir(parents=True, exist_ok=True)
    return h


def existing(uhome):
    (uhome / ".claude" / "settings.json").write_text(json.dumps({
        "model": "opus", "permissions": {"allow": ["Bash(git status)"]},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-hook.sh"}]}],
                  "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]}}), encoding="utf-8")
    (uhome / ".cursor" / "hooks.json").write_text(json.dumps({
        "version": 1, "hooks": {"afterFileEdit": [{"command": "./hooks/format.sh"}],
                                "beforeShellExecution": [{"command": "./hooks/audit.sh"}]}}), encoding="utf-8")
    (uhome / ".gemini" / "config" / "hooks.json").write_text(json.dumps({
        "my-gate": {"PreToolUse": [{"matcher": "run_command", "hooks": [{"command": "x.sh"}]}]}}), encoding="utf-8")


def load(p):
    return json.loads(p.read_text(encoding="utf-8"))


def test_install_merges_and_backs_up(uhome):
    existing(uhome)
    assert installer.install(add_path=False, out=lambda *_: None) == 0
    c = load(uhome / ".claude" / "settings.json")
    assert c["model"] == "opus" and c["permissions"]["allow"] == ["Bash(git status)"]
    cmds = [h["command"] for g in c["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "my-hook.sh" in cmds and any(installer.MARKER in x for x in cmds)
    ours = [h for g in c["hooks"]["PreToolUse"] for h in g["hooks"] if installer.MARKER in h["command"]][0]
    assert ours["onFailure"] == "block" and ours["timeout"] == installer.HOOK_TIMEOUT
    assert c["hooks"]["Stop"]
    cur = load(uhome / ".cursor" / "hooks.json")
    assert cur["hooks"]["afterFileEdit"] and len(cur["hooks"]["beforeShellExecution"]) == 2
    assert all(h["failClosed"] for h in cur["hooks"]["preToolUse"])
    ag = load(uhome / ".gemini" / "config" / "hooks.json")
    assert "my-gate" in ag and "depbouncer" in ag
    cx = load(uhome / ".codex" / "hooks.json")
    assert cx["hooks"]["PreToolUse"][0]["matcher"] == "Bash|apply_patch|Edit|Write"
    backups = list((Path(os.environ["DEPBOUNCER_HOME"]) / "backups").rglob("*.json"))
    assert len(backups) == 3          # claude, cursor, antigravity existed; codex did not
    for skill in ("claude", "codex", "antigravity"):
        assert (installer.skill_dirs()[skill] / "SKILL.md").exists()
    hookcmd = Path(os.environ["DEPBOUNCER_HOME"]) / "bin" / "depbouncer-hook.cmd"
    assert "exit /b 2" in hookcmd.read_text()


def test_install_is_idempotent(uhome):
    existing(uhome)
    installer.install(add_path=False, out=lambda *_: None)
    installer.install(add_path=False, out=lambda *_: None)
    c = load(uhome / ".claude" / "settings.json")
    ours = [h for g in c["hooks"]["PreToolUse"] for h in g["hooks"] if installer.MARKER in h["command"]]
    assert len(ours) == 1
    cur = load(uhome / ".cursor" / "hooks.json")
    assert sum(installer.MARKER in h["command"] for h in cur["hooks"]["beforeShellExecution"]) == 1


def test_uninstall_removes_only_ours(uhome):
    existing(uhome)
    before = {p: load(p) for p in [uhome / ".claude" / "settings.json", uhome / ".cursor" / "hooks.json",
                                   uhome / ".gemini" / "config" / "hooks.json"]}
    installer.install(add_path=False, out=lambda *_: None)
    installer.uninstall(out=lambda *_: None)
    for p, data in before.items():
        assert load(p) == data, p
    assert installer.MARKER not in (uhome / ".codex" / "hooks.json").read_text(encoding="utf-8")
    assert not (installer.skill_dirs()["claude"] / "SKILL.md").exists()


def test_invalid_json_is_left_untouched(uhome):
    bad = uhome / ".claude" / "settings.json"
    bad.write_text("{ broken", encoding="utf-8")
    assert installer.install(agents=["claude"], add_path=False, out=lambda *_: None) == 1
    assert bad.read_text(encoding="utf-8") == "{ broken"


def test_foreign_skill_not_overwritten(uhome):
    d = installer.skill_dirs()["claude"]
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("my own pc-scan", encoding="utf-8")
    installer.install(agents=["claude"], add_path=False, out=lambda *_: None)
    assert (d / "SKILL.md").read_text(encoding="utf-8") == "my own pc-scan"


def test_dry_run_changes_nothing(uhome):
    existing(uhome)
    snap = (uhome / ".claude" / "settings.json").read_text(encoding="utf-8")
    installer.install(dry_run=True, add_path=False, out=lambda *_: None)
    assert (uhome / ".claude" / "settings.json").read_text(encoding="utf-8") == snap
    assert not (uhome / ".codex" / "hooks.json").exists()


def test_store_python_refused(monkeypatch):
    monkeypatch.setattr(installer.sys, "executable",
                        r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\python.exe")
    with pytest.raises(RuntimeError):
        installer.real_python()


@pytest.mark.skipif(os.name != "nt", reason="Windows hook launcher")
def test_installed_hook_cmd_fails_closed_when_python_missing(uhome, tmp_path):
    import subprocess
    installer.install(agents=["claude"], add_path=False, out=lambda *_: None)
    hookcmd = Path(os.environ["DEPBOUNCER_HOME"]) / "bin" / "depbouncer-hook.cmd"
    text = hookcmd.read_text()
    broken = tmp_path / "broken-hook.cmd"
    broken.write_text(text.replace(os.path.basename(installer.sys.executable), "no-such-python.exe"))
    r = subprocess.run(["cmd", "/d", "/c", str(broken), "claude"], input="{}", capture_output=True, text=True)
    assert r.returncode == 2
    for agent, key in (("codex", "permissionDecision"), ("antigravity", "decision")):
        r = subprocess.run(["cmd", "/d", "/c", str(broken), agent], input="{}", capture_output=True, text=True)
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert (d.get("hookSpecificOutput", d))[key] == "deny"
    ok = subprocess.run(["cmd", "/d", "/c", str(hookcmd), "claude"], input=json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "echo hi"}}), capture_output=True, text=True, timeout=60)
    assert ok.returncode == 0
    bad = subprocess.run(["cmd", "/d", "/c", str(hookcmd), "claude"], input="garbage",
                         capture_output=True, text=True, timeout=60)
    assert bad.returncode == 2
