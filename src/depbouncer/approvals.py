"""User approvals for ASK results.

An approval is for one exact package and version, is used once, and expires
after 30 minutes. It can only be given through a native Windows dialog (or a
typed code on a real terminal elsewhere), so an agent cannot approve its own
request by running a command. The hooks also deny any agent command or edit
that touches these files.

Limit: the agent runs as the same Windows user. A determined agent that
evades the hooks could still write these files; this raises the bar, it is
not an OS-level boundary.
"""
import os
import secrets
import sys
import time

from .config import data_dir, read_json, write_json_atomic

TTL = 30 * 60
PENDING_TTL = 24 * 3600


def _p(name):
    return data_dir() / name


def add_pending(key, display, reasons_text, agent):
    pend = read_json(_p("pending.json"), {})
    now = time.time()
    pend = {k: v for k, v in pend.items() if now - v.get("created", 0) < PENDING_TTL}
    pend[key] = {"display": display, "reasons": reasons_text, "created": now, "agent": agent}
    write_json_atomic(_p("pending.json"), pend)


def pending():
    now = time.time()
    return {k: v for k, v in read_json(_p("pending.json"), {}).items() if now - v.get("created", 0) < PENDING_TTL}


def is_approved(key):
    a = read_json(_p("approvals.json"), {}).get(key)
    return bool(a) and a.get("expires", 0) > time.time() and not a.get("used")


def consume(key):
    ap = read_json(_p("approvals.json"), {})
    if key in ap:
        ap[key]["used"] = True
        ap = {k: v for k, v in ap.items() if v.get("expires", 0) > time.time() and not v.get("used")}
        write_json_atomic(_p("approvals.json"), ap)
    pend = read_json(_p("pending.json"), {})
    if pend.pop(key, None) is not None:
        write_json_atomic(_p("pending.json"), pend)


def grant(key):
    ap = read_json(_p("approvals.json"), {})
    ap[key] = {"expires": time.time() + TTL, "granted": time.time()}
    write_json_atomic(_p("approvals.json"), ap)


def _dialog_windows(title, body):
    import ctypes
    MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2 = 0x4, 0x30, 0x100
    MB_TOPMOST, MB_SETFOREGROUND = 0x40000, 0x10000
    res = ctypes.windll.user32.MessageBoxW(None, body, title,
                                           MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND)
    return res == 6  # IDYES


def _prompt_tty(body):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("depbouncer: approval needs a real terminal / onay için gerçek bir terminal gerekir", file=sys.stderr)
        return False
    code = f"{secrets.randbelow(10000):04d}"
    print(body)
    print(f"\nOnaylamak için {code} yazın / Type {code} to approve: ", end="", flush=True)
    return sys.stdin.readline().strip() == code


def ask_human(key, info, dialog=None):
    title = "depbouncer"
    body = (f"Bir yapay zekâ ajanı şu paketi kurmak istiyor / An AI agent wants to install:\n\n"
            f"{info.get('display', key)}\n\n{info.get('reasons', '')}\n\n"
            "Yalnızca bu kurulumu siz istediyseniz EVET deyin.\n"
            "Say YES only if you asked for this install.\n\n"
            "(Tek kullanımlık, 30 dakika geçerli / single use, valid 30 minutes)")
    if dialog is None:
        dialog = _dialog_windows if os.name == "nt" else (lambda t, b: _prompt_tty(b))
    return dialog(title, body)


def approve(keys=None, dialog=None, out=print):
    pend = pending()
    targets = keys or list(pend)
    if not targets:
        out("Onay bekleyen paket yok / Nothing is waiting for approval.")
        return 0
    granted = 0
    for k in targets:
        info = pend.get(k)
        if info is None:
            out(f"Bekleyen kayıt bulunamadı / No pending request: {k}")
            continue
        if ask_human(k, info, dialog):
            grant(k)
            granted += 1
            out(f"ONAYLANDI / APPROVED (30 dk/min, tek kullanım/single use): {info.get('display', k)}")
        else:
            out(f"Reddedildi / Declined: {info.get('display', k)}")
    return 0 if granted else 1
