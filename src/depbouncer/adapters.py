"""Translate each agent's hook input into a Request and our decision back
into the agent's output format.

Sources (read 2026-11-25):
- Claude Code  https://code.claude.com/docs/en/hooks        (PreToolUse, permissionDecision allow/deny/ask)
- Codex        https://learn.chatgpt.com/docs/hooks          (PreToolUse; "ask" is parsed but NOT supported)
- Cursor       https://cursor.com/docs/agent/hooks           (ask works only in beforeShellExecution/MCP)
- Antigravity  https://antigravity.google/docs/hooks         (decision allow/deny/ask/force_ask)
"""
import json
import os

from .guard import Edit, Request

CLAUDE_SAFE_MODES = {"default", "plan", "acceptEdits"}


def _read(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    except OSError:
        return None


def _abs(path, cwd):
    if not path:
        return path
    path = os.path.expanduser(str(path))
    return path if os.path.isabs(path) else os.path.join(cwd or os.getcwd(), path)


def _replace(text, pairs):
    if text is None:
        return None
    for old, new, many in pairs:
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        if old == "":
            if text == "":
                text = new
                continue
            return None
        if old not in text:
            return None
        text = text.replace(old, new) if many else text.replace(old, new, 1)
    return text


_PATH_KEYS = ("file_path", "path", "target_file", "TargetFile", "filePath", "filename", "file", "AbsolutePath")
_CONTENT_KEYS = ("content", "contents", "CodeContent", "file_text", "text", "new_content", "newContent")


def generic_edit(args, cwd):
    """Best-effort edit reconstruction for tools whose input format is not
    documented (Cursor preToolUse, unknown tools). None = not a file edit."""
    if not isinstance(args, dict):
        return None
    path = next((args[k] for k in _PATH_KEYS if isinstance(args.get(k), str)), None)
    if not path:
        return None
    path = _abs(path, cwd)
    old = _read(path)
    content = next((args[k] for k in _CONTENT_KEYS if isinstance(args.get(k), str)), None)
    if content is not None and not any(k in args for k in ("old_string", "TargetContent")):
        return Edit(path, old, content)
    pairs = []
    if "old_string" in args:
        pairs.append((args.get("old_string"), args.get("new_string"), bool(args.get("replace_all"))))
    if "TargetContent" in args:
        pairs.append((args.get("TargetContent"), args.get("ReplacementContent"), bool(args.get("AllowMultiple"))))
    for key in ("edits", "ReplacementChunks", "chunks"):
        for ch in args.get(key) or []:
            if isinstance(ch, dict):
                o = ch.get("old_string", ch.get("TargetContent", ch.get("oldText")))
                n = ch.get("new_string", ch.get("ReplacementContent", ch.get("newText")))
                pairs.append((o, n, bool(ch.get("replace_all") or ch.get("AllowMultiple"))))
    if pairs:
        return Edit(path, old, _replace(old if old is not None else "", pairs))
    return Edit(path, old, None)


def apply_patch_edits(patch, cwd):
    """Codex apply_patch format -> list of Edit."""
    edits, cur, lines = [], None, patch.splitlines()

    def flush():
        if cur is None:
            return
        path, mode, hunks, added = cur
        if mode == "add":
            edits.append(Edit(path, _read(path), "\n".join(added) + "\n"))
        elif mode == "update":
            text = _read(path)
            if text is None:
                edits.append(Edit(path, None, None))
                return
            new = text
            for h in hunks:
                old_b = "\n".join(l[1:] for l in h if l[:1] in (" ", "-"))
                new_b = "\n".join(l[1:] for l in h if l[:1] in (" ", "+"))
                if old_b and old_b not in new:
                    new = None
                    break
                new = new.replace(old_b, new_b, 1) if old_b else new + new_b
            edits.append(Edit(path, text, new))

    hunk = None
    for line in lines:
        if line.startswith("*** Add File: "):
            flush()
            cur, hunk = (_abs(line[14:].strip(), cwd), "add", [], []), None
        elif line.startswith("*** Update File: "):
            flush()
            hunk = []
            cur = (_abs(line[17:].strip(), cwd), "update", [hunk], [])
        elif line.startswith("*** Delete File: ") or line.startswith("*** End Patch") or \
                line.startswith("*** Begin Patch"):
            flush()
            cur, hunk = None, None
        elif line.startswith("*** Move to: ") and cur:
            pass
        elif line.startswith("*** End of File"):
            continue
        elif cur and cur[1] == "add":
            if line.startswith("+"):
                cur[3].append(line[1:])
        elif cur and cur[1] == "update":
            if line.startswith("@@"):
                hunk = []
                cur[2].append(hunk)
            elif line[:1] in (" ", "-", "+") or line == "":
                hunk.append(line if line else " ")
    flush()
    return edits


# ------------------------------------------------------------------ inputs
def from_claude(d):
    tool, ti, cwd = d.get("tool_name", ""), d.get("tool_input") or {}, d.get("cwd")
    mode = d.get("permission_mode")
    req = Request("claude", cwd=cwd, permission_mode=mode, native_ask=mode in CLAUDE_SAFE_MODES)
    if tool in ("Bash", "PowerShell"):
        req.command = ti.get("command", "")
    elif tool == "Write":
        p = _abs(ti.get("file_path"), cwd)
        req.edits.append(Edit(p, _read(p), ti.get("content")))
    elif tool == "Edit":
        p = _abs(ti.get("file_path"), cwd)
        old = _read(p)
        req.edits.append(Edit(p, old, _replace(old, [(ti.get("old_string"), ti.get("new_string"),
                                                      bool(ti.get("replace_all")))])))
    elif tool == "MultiEdit":
        p = _abs(ti.get("file_path"), cwd)
        old = _read(p)
        pairs = [(e.get("old_string"), e.get("new_string"), bool(e.get("replace_all"))) for e in ti.get("edits", [])]
        req.edits.append(Edit(p, old, _replace(old if old is not None else "", pairs)))
    else:
        e = generic_edit(ti, cwd)
        if e:
            req.edits.append(e)
    return req


def _codex_command(ti):
    c = ti.get("command", "")
    if isinstance(c, list):
        if len(c) >= 3 and c[1] in ("-lc", "-c", "/c", "-Command", "-command"):
            return c[2]
        return " ".join(map(str, c))
    return c or ""


def from_codex(d):
    tool, ti, cwd = d.get("tool_name", ""), d.get("tool_input") or {}, d.get("cwd")
    req = Request("codex", cwd=cwd, permission_mode=d.get("permission_mode"), native_ask=False)
    if tool in ("apply_patch", "Edit", "Write") and not ("file_path" in ti):
        patch = ti.get("command") or ti.get("patch") or ti.get("input") or ""
        if isinstance(patch, list):
            patch = "\n".join(map(str, patch))
        if "*** Begin Patch" in patch or "*** Update File" in patch or "*** Add File" in patch:
            req.edits += apply_patch_edits(patch, cwd)
        else:
            req.command = _codex_command(ti)
    elif tool == "Bash" or "command" in ti:
        req.command = _codex_command(ti)
    else:
        e = generic_edit(ti, cwd)
        if e:
            req.edits.append(e)
    return req


def from_cursor(d):
    ev = d.get("hook_event_name", "")
    roots = d.get("workspace_roots") or []
    cwd = d.get("cwd") or (roots[0] if roots else None)
    if ev == "beforeShellExecution":
        return Request("cursor", command=d.get("command", ""), cwd=cwd, native_ask=True)
    ti = d.get("tool_input") or {}
    if isinstance(ti, str):
        try:
            ti = json.loads(ti)
        except ValueError:
            ti = {}
    cwd = ti.get("cwd") or cwd
    req = Request("cursor", cwd=cwd, native_ask=False)   # preToolUse: "ask" is not enforced
    tool = d.get("tool_name", "")
    if tool == "Shell" or ("command" in ti and isinstance(ti.get("command"), str)):
        req.command = ti.get("command", "")
    elif "delete" not in tool.lower():
        e = generic_edit(ti, cwd)
        if e:
            req.edits.append(e)
    return req


def from_antigravity(d):
    tc = d.get("toolCall") or {}
    name, args = tc.get("name", ""), tc.get("args") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {}
    roots = d.get("workspacePaths") or []
    cwd = args.get("Cwd") or (roots[0] if roots else None)
    req = Request("antigravity", cwd=cwd, native_ask=True)
    if name == "run_command" or "CommandLine" in args:
        req.command = args.get("CommandLine", "")
    else:
        e = generic_edit(args, cwd)
        if e:
            req.edits.append(e)
    return req


PARSE = {"claude": from_claude, "codex": from_codex, "cursor": from_cursor, "antigravity": from_antigravity}

# How each agent is told "blocked" when something went wrong:
# Claude Code and Cursor document exit 2 as "block" (plus onFailure/failClosed);
# Codex and Antigravity get a JSON deny with exit 0 (see output()).
FAIL_EXIT = {"claude": 2, "cursor": 2, "codex": 0, "antigravity": 0}


# ----------------------------------------------------------------- outputs
def output(agent, verdict, message, native_ask, relevant, event=None):
    """Return (stdout_text, exit_code). verdict in PASS / ASK / DENY.
    PASS never grants extra permission: the agent's normal permission flow
    still applies (Claude/Codex: no decision; Cursor/Antigravity: "allow",
    not "auto_approve")."""
    if agent == "claude":
        if verdict == "PASS":
            return (json.dumps({"systemMessage": message}) if relevant else ""), 0
        dec = "ask" if verdict == "ASK" else "deny"
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": dec,
                                                  "permissionDecisionReason": message},
                           "systemMessage": message}), 0
    if agent == "codex":
        if verdict == "PASS":
            return "", 0
        # Verified with codex-cli 0.167: JSON deny + exit 0 shows "Blocked" and the
        # reason reaches the model; JSON + exit 2 is reported as a failed hook.
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                  "permissionDecisionReason": message}}), 0
    if agent == "cursor":
        perm = {"PASS": "allow", "ASK": "ask", "DENY": "deny"}[verdict]
        out = {"permission": perm}
        if relevant or verdict != "PASS":
            out["user_message"] = message
            out["agent_message"] = message
        if event == "beforeShellExecution":
            out["continue"] = True
        return json.dumps(out), (2 if verdict == "DENY" else 0)
    if agent == "antigravity":
        dec = {"PASS": "allow", "ASK": "force_ask", "DENY": "deny"}[verdict]
        out = {"decision": dec}
        if relevant or verdict != "PASS":
            out["reason"] = message
        return json.dumps(out), 0
    raise ValueError(agent)
