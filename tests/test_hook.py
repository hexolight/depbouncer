"""End-to-end hook behaviour per agent, with fake registry results."""
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from depbouncer import approvals, checker, hook
from depbouncer.checker import Result

VERDICTS = {"goodpkg": "PASS", "askpkg": "ASK", "evilpkg": "BLOCK"}


@pytest.fixture(autouse=True)
def fake_check(monkeypatch):
    calls = []

    def fake(eco, name, spec, cfg=None, deadline=None, transitive_fn=None):
        calls.append((eco, name, spec))
        v = VERDICTS.get(name, "PASS")
        reasons = {"PASS": [], "ASK": [("new_package", {"days": 90})], "BLOCK": [("known_malware", {"ids": "MAL-1"})]}
        return Result(v, reasons[v], [("fact_version", {"v": "1.0.0"})], "1.0.0")
    monkeypatch.setattr(checker, "check", fake)
    return calls


def run(agent, payload, **kw):
    out, err = io.StringIO(), io.StringIO()
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    code = hook.main(agent, io.StringIO(raw), out, err, **kw)
    text = out.getvalue()
    return code, (json.loads(text) if text.strip() else None), err.getvalue()


def claude(cmd, mode="default"):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd},
            "cwd": os.getcwd(), "permission_mode": mode}


def codex(cmd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": os.getcwd()}


def cursor_shell(cmd):
    return {"hook_event_name": "beforeShellExecution", "command": cmd, "cwd": os.getcwd()}


def ag(cmd):
    return {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": os.getcwd()}}}


# ---------------------------------------------------------------- Claude Code
def test_claude_pass_no_decision():
    code, out, _ = run("claude", claude("npm i goodpkg"))
    assert code == 0 and "hookSpecificOutput" not in out and "GEÇTİ" in out["systemMessage"]


def test_claude_irrelevant_silent():
    code, out, _ = run("claude", claude("git status"))
    assert code == 0 and out is None


def test_claude_ask_native():
    code, out, _ = run("claude", claude("npm i askpkg"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "ONAY GEREKİYOR" in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("mode", ["bypassPermissions", "dontAsk", "auto", None])
def test_claude_ask_becomes_deny_when_agent_could_self_approve(mode):
    code, out, _ = run("claude", claude("npm i askpkg", mode))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "depbouncer approve" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert approvals.pending()


def test_claude_block():
    code, out, _ = run("claude", claude("pip install evilpkg"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "ENGELLENDİ" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_claude_edit_package_json(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {"goodpkg": "1.0.0"}}', encoding="utf-8")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(tmp_path),
               "permission_mode": "default",
               "tool_input": {"file_path": str(pj), "old_string": '"goodpkg": "1.0.0"',
                              "new_string": '"goodpkg": "1.0.0", "evilpkg": "1.0.0"'}}
    code, out, _ = run("claude", payload)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_write_requirements(tmp_path):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(tmp_path),
               "permission_mode": "default",
               "tool_input": {"file_path": str(tmp_path / "requirements.txt"), "content": "askpkg==1.0\n"}}
    assert run("claude", payload)[1]["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_claude_bare_install_reads_manifest(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"evilpkg": "^1.0.0"}}', encoding="utf-8")
    payload = {**claude("npm install"), "cwd": str(tmp_path)}
    assert run("claude", payload)[1]["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---------------------------------------------------------------------- Codex
def test_codex_pass_silent():
    assert run("codex", codex("npm i goodpkg")) == (0, None, "")


def denied(agent, code, out):
    """Blocked in the way each agent understands (see adapters.FAIL_EXIT)."""
    if out is None:
        return False
    if agent == "codex":
        return code == 0 and out["hookSpecificOutput"]["permissionDecision"] == "deny"
    if agent == "antigravity":
        return code == 0 and out["decision"] == "deny"
    if agent == "cursor":
        return code == 2 and out["permission"] == "deny"
    return code == 2 or out["hookSpecificOutput"]["permissionDecision"] == "deny"


def cx(cmd):
    code, out, _ = run("codex", codex(cmd))
    return "deny" if denied("codex", code, out) else "pass" if out is None and code == 0 else "?"


def test_codex_ask_is_deny_with_approval_path():
    code, out, err = run("codex", codex("npm i askpkg"))
    assert denied("codex", code, out)
    assert "depbouncer approve" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_apply_patch(tmp_path):
    (tmp_path / "requirements.txt").write_text("goodpkg==1.0\n", encoding="utf-8")
    patch = ("*** Begin Patch\n*** Update File: requirements.txt\n@@\n goodpkg==1.0\n+evilpkg==1.0\n"
             "*** End Patch\n")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": str(tmp_path),
               "tool_input": {"command": patch}}
    code, out, _ = run("codex", payload)
    assert denied("codex", code, out)


def test_codex_argv_command():
    payload = {"tool_name": "Bash", "tool_input": {"command": ["bash", "-lc", "pip install evilpkg"]}}
    assert denied("codex", *run("codex", payload)[:2])


# --------------------------------------------------------------------- Cursor
def test_cursor_shell_ask_native():
    code, out, _ = run("cursor", cursor_shell("pnpm add askpkg"))
    assert code == 0 and out["permission"] == "ask"


def test_cursor_irrelevant_allows():
    code, out, _ = run("cursor", cursor_shell("ls"))
    assert out == {"permission": "allow", "continue": True}


def test_cursor_pretooluse_ask_becomes_deny(tmp_path):
    payload = {"hook_event_name": "preToolUse", "tool_name": "Write", "workspace_roots": [str(tmp_path)],
               "tool_input": {"file_path": str(tmp_path / "package.json"),
                              "contents": '{"dependencies": {"askpkg": "1.0.0"}}'}}
    code, out, _ = run("cursor", payload)
    assert code == 2 and out["permission"] == "deny"


def test_cursor_unknown_edit_format_is_ask(tmp_path):
    payload = {"hook_event_name": "preToolUse", "tool_name": "Write",
               "tool_input": {"file_path": str(tmp_path / "package.json"), "weird": 1}}
    code, out, _ = run("cursor", payload)
    assert out["permission"] == "deny"   # cannot evaluate -> ASK -> deny (ask not enforced in preToolUse)


# ---------------------------------------------------------------- Antigravity
def test_antigravity_force_ask():
    code, out, _ = run("antigravity", ag("npm i askpkg"))
    assert out["decision"] == "force_ask"


def test_antigravity_block_and_allow():
    assert run("antigravity", ag("npm i evilpkg"))[1]["decision"] == "deny"
    assert run("antigravity", ag("dir"))[1] == {"decision": "allow"}


def test_antigravity_replace_file_content(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {}}', encoding="utf-8")
    payload = {"toolCall": {"name": "replace_file_content", "args": {
        "TargetFile": str(pj), "TargetContent": '"dependencies": {}',
        "ReplacementContent": '"dependencies": {"evilpkg": "1.0.0"}'}}}
    assert run("antigravity", payload)[1]["decision"] == "deny"


# -------------------------------------------------------------- fail closed
def test_bom_prefixed_input_is_understood():
    # PowerShell/.NET pipes add a UTF-8 BOM; found during the real Windows shell trial.
    code, out, _ = run("antigravity", "﻿" + json.dumps(ag("dir")))
    assert code == 0 and out == {"decision": "allow"}


@pytest.mark.parametrize("agent", ["claude", "codex", "cursor", "antigravity"])
def test_garbage_input_denies(agent):
    code, out, err = run(agent, "this is not json")
    assert denied(agent, code, out)


@pytest.mark.parametrize("agent", ["claude", "codex", "cursor", "antigravity"])
def test_crash_denies(agent, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(checker, "check", boom)
    payload = {"claude": claude("npm i x"), "codex": codex("npm i x"), "cursor": cursor_shell("npm i x"),
               "antigravity": ag("npm i x")}[agent]
    code, out, err = run(agent, payload)
    assert denied(agent, code, out) and "kaboom" in err


def test_timeout_denies(monkeypatch):
    monkeypatch.setattr(checker, "check", lambda *a, **k: time.sleep(5))
    t = time.monotonic()
    code, out, err = run("claude", claude("npm i slowpkg"), deadline_seconds=1)
    assert code == 2 and time.monotonic() - t < 4
    assert "zaman aşımı" in err


def test_launcher_import_failure_denies(tmp_path):
    src = Path(__file__).resolve().parent.parent / "src" / "launcher.py"
    lone = tmp_path / "launcher.py"          # no depbouncer package next to it
    lone.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(lone), "hook", "claude"], input="{}",
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ------------------------------------------------------------ approvals
def test_approval_flow_single_use():
    assert cx("npm i askpkg") == "deny"
    pend = approvals.pending()
    assert list(pend) == ["npm:askpkg@1.0.0"]
    assert approvals.approve(dialog=lambda t, b: True, out=lambda *_: None) == 0
    assert cx("npm i askpkg") == "pass"     # approved once
    assert cx("npm i askpkg") == "deny"     # used up


def test_declined_dialog_grants_nothing():
    cx("npm i askpkg")
    assert approvals.approve(dialog=lambda t, b: False, out=lambda *_: None) == 1
    assert cx("npm i askpkg") == "deny"


def test_approval_expires(monkeypatch):
    cx("npm i askpkg")
    approvals.approve(dialog=lambda t, b: True, out=lambda *_: None)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + approvals.TTL + 5)
    assert cx("npm i askpkg") == "deny"


def test_block_cannot_be_approved():
    cx("npm i evilpkg")
    approvals.grant("npm:evilpkg@1.0.0")
    assert cx("npm i evilpkg") == "deny"


@pytest.mark.parametrize("cmd", [
    "depbouncer approve",
    "C:/Users/x/AppData/Local/depbouncer/bin/depbouncer.cmd approve npm:askpkg@1.0.0",
    "echo {} > %LOCALAPPDATA%\\depbouncer\\approvals.json",
    "Set-Content $env:LOCALAPPDATA\\depbouncer\\config.toml 'x'",
    "python -c \"open('C:/Users/x/.claude/settings.json','w')\"",
    "Remove-Item ~/.cursor/hooks.json",
])
def test_agent_cannot_tamper(cmd):
    code, out, _ = run("claude", claude(cmd))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "koruma" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_repo_uninstall_script_is_tamper(tmp_path):
    (tmp_path / "uninstall.ps1").write_text("# depbouncer uninstaller\n", encoding="utf-8")
    (tmp_path / "install.ps1").write_text("Write-Host other project\n", encoding="utf-8")
    for cmd, want in (("powershell -ExecutionPolicy Bypass -File .\\uninstall.ps1", "deny"),
                      ("powershell -File install.ps1", None)):
        req = claude(cmd)
        req["cwd"] = str(tmp_path)
        code, out, _ = run("claude", req)
        got = (out or {}).get("hookSpecificOutput", {}).get("permissionDecision")
        assert got == want, cmd


def test_reading_settings_is_fine():
    assert run("claude", claude("cat ~/.claude/settings.json"))[1] is None
    assert run("claude", claude("C:/Users/x/AppData/Local/depbouncer/bin/depbouncer.cmd scan --status"))[1] is None


def test_edit_to_agent_settings_blocked(tmp_path):
    target = Path.home() / ".claude" / "settings.json"
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Write", "permission_mode": "default",
               "tool_input": {"file_path": str(target), "content": '{"disableAllHooks": true}'}}
    assert run("claude", payload)[1]["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_private_packages_never_checked(fake_check, tmp_path):
    d = Path(os.environ["DEPBOUNCER_HOME"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.toml").write_text('[private]\nnpm = ["@mycorp/*"]\nresult = "ask"\n', encoding="utf-8")
    code, out, _ = run("claude", claude("npm i @mycorp/secret-lib"))
    assert fake_check == []
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_english_only(tmp_path):
    d = Path(os.environ["DEPBOUNCER_HOME"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.toml").write_text('lang = "en"\n', encoding="utf-8")
    out = run("claude", claude("npm i evilpkg"))[1]
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "BLOCKED" in reason and "ENGELLENDİ" not in reason
