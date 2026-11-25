"""Entry script used by the installed hooks and CLI.

Run with `python -I launcher.py ...`. -I ignores PYTHON* variables, the user
site folder and the current folder, so a planted file in the project cannot
replace our modules. If even importing fails, the hook still answers "deny".
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DENY = {
    "claude": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": "depbouncer could not start: failing safe"}},
    "codex": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                     "permissionDecisionReason": "depbouncer could not start: failing safe"}},
    "cursor": {"permission": "deny", "user_message": "depbouncer could not start: failing safe"},
    "antigravity": {"decision": "deny", "reason": "depbouncer could not start: failing safe"},
}

if __name__ == "__main__":
    is_hook = len(sys.argv) >= 3 and sys.argv[1] == "hook"
    try:
        from depbouncer.cli import main
        code = main(sys.argv[1:])
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except BaseException as e:  # noqa: BLE001
        if is_hook:
            sys.stdout.write(json.dumps(DENY.get(sys.argv[2], DENY["antigravity"])))
            sys.stderr.write(f"depbouncer could not start: {type(e).__name__}: {e}\n")
            # Claude Code / Cursor: exit 2 = block. Codex / Antigravity: JSON deny + exit 0.
            code = 0 if sys.argv[2] in ("codex", "antigravity") else 2
        else:
            raise
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code if isinstance(code, int) else 1)
