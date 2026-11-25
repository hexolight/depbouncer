"""Hook entry point. Fail closed: crash, timeout, bad input or an uncertain
result never lets an install through.

Exit codes: 0 = decision is in the JSON on stdout; 2 = blocked (all four
agents treat 2 as "block"; the reason also goes to stderr).
"""
import json
import os
import sys
import threading
import time
import traceback

from . import adapters, guard, i18n
from .config import load

DEADLINE_SECONDS = float(os.environ.get("DEPBOUNCER_DEADLINE", "90"))


def decide(agent, raw, cfg, deadline):
    # .NET / PowerShell pipes often start with a UTF-8 BOM.
    raw = raw.lstrip("﻿￾\x00 \r\n\t")
    if raw.startswith("ï»¿"):
        raw = raw[3:]
    try:
        data = json.loads(raw) if raw.strip() else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        msg = "depbouncer: " + i18n.pick(i18n.VERDICT["BLOCK"], cfg.lang) + " — " + \
              i18n.text("undecidable_input", {}, cfg.lang)
        text, _ = adapters.output(agent, "DENY", msg, False, True)
        return text, adapters.FAIL_EXIT[agent]
    req = adapters.PARSE[agent](data)
    out = guard.evaluate(req, cfg, deadline)
    native = req.native_ask and cfg.ask_mode == "auto"
    guard.finalize(out, req, cfg, deny_instead_of_ask=not native)
    msg = guard.render(out, cfg, approval_hint=not native)
    if out.verdict == "PASS":
        return adapters.output(agent, "PASS", msg, native, out.relevant, data.get("hook_event_name"))
    if out.verdict == "ASK" and native:
        return adapters.output(agent, "ASK", msg, native, True, data.get("hook_event_name"))
    return adapters.output(agent, "DENY", msg, native, True, data.get("hook_event_name"))


def fail_closed(agent, lang, code, params):
    msg = f"depbouncer: {i18n.pick(i18n.VERDICT['BLOCK'], lang)} — {i18n.text(code, params, lang)}"
    try:
        text, _ = adapters.output(agent, "DENY", msg, False, True)
        code = adapters.FAIL_EXIT[agent]
    except Exception:  # noqa: BLE001
        text, code = json.dumps({"decision": "deny", "permission": "deny", "reason": msg}), 2
    return text, code, msg


def main(agent, stdin=None, stdout=None, stderr=None, deadline_seconds=None):
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    lang = "both"
    result = {}

    def work():
        nonlocal lang
        try:
            cfg = load()
            lang = cfg.lang
            raw = stdin.read()
            budget = deadline_seconds or DEADLINE_SECONDS
            text, code = decide(agent, raw, cfg, time.monotonic() + budget - 5)
            result["out"] = (text, code, None)
        except BaseException as e:  # noqa: BLE001
            traceback.print_exc(file=stderr)
            result["out"] = fail_closed(agent, lang, "internal_error", {"err": f"{type(e).__name__}: {e}"[:200]})

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(deadline_seconds or DEADLINE_SECONDS)
    if "out" not in result:
        text, code, msg = fail_closed(agent, lang, "timeout", {})
    else:
        text, code, msg = result["out"]
    if text:
        stdout.write(text)
        stdout.flush()
    if code == 2:
        if msg is None:
            try:
                d = json.loads(text)
                msg = (d.get("hookSpecificOutput", {}).get("permissionDecisionReason") or d.get("user_message")
                       or d.get("reason") or "blocked")
            except ValueError:
                msg = "blocked"
        stderr.write(msg + "\n")
        stderr.flush()
    return code
