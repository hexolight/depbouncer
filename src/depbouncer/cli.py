"""Command line: depbouncer <command> ..."""
import argparse
import sys

from . import __version__


def _utf8():
    for s in (sys.stdin, sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def cmd_check(a):
    from . import commands, guard
    from .checker import ORDER
    from .config import load
    from .guard import Item, Outcome
    cfg = load()
    if a.lang:
        cfg.lang = a.lang
    if a.no_transitive:
        cfg.transitive = False
    items = []
    for spec in a.specs:
        if a.eco == "npm":
            it = commands.npm_spec(spec)
        elif a.eco == "pypi":
            s = spec.replace("@", "==", 1) if "@" in spec and "==" not in spec else spec
            it = commands.pip_spec(s)
        else:
            n, _, v = spec.partition("@")
            it = commands.Intent(eco="nuget", name=n, spec=v or None, origin=spec)
        if it is None:
            continue
        r = guard.check_one(it, cfg, None, use_cache=False)
        items.append(Item(guard.label(it, r), r, guard.approval_key(it, r)))
    worst = max((ORDER.index(i.result.verdict) for i in items), default=1)
    print(guard.render(Outcome(ORDER[worst], items, True), cfg, approval_hint=False))
    return worst


def cmd_hook(a):
    from . import hook
    return hook.main(a.agent)


def cmd_approve(a):
    from . import approvals
    return approvals.approve(a.keys or None)


def cmd_pending(a):
    from . import approvals
    p = approvals.pending()
    if not p:
        print("Onay bekleyen paket yok / Nothing is waiting for approval.")
    for k, v in p.items():
        print(f"{k}\n    {v.get('display')}  [{v.get('agent')}]\n    {v.get('reasons')}")
    return 0


def cmd_scan(a):
    from . import scan
    if a.status:
        return scan.status()
    return scan.run(roots=a.roots or None, restart=a.restart, lang=a.lang)


def cmd_install(a):
    from . import installer
    return installer.install(agents=a.agents, dry_run=a.dry_run, add_path=not a.no_path)


def cmd_uninstall(a):
    from . import installer
    return installer.uninstall(dry_run=a.dry_run, purge=a.purge)


def cmd_doctor(a):
    from . import installer
    return installer.doctor()


def build():
    p = argparse.ArgumentParser(prog="depbouncer", description="Guards packages installed by AI agents.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check packages by hand (exit 0 PASS, 1 ASK, 2 BLOCK)")
    c.add_argument("eco", choices=["npm", "pypi", "nuget"])
    c.add_argument("specs", nargs="+")
    c.add_argument("--lang", choices=["tr", "en", "both"])
    c.add_argument("--no-transitive", action="store_true")
    c.set_defaults(fn=cmd_check)
    h = sub.add_parser("hook", help="(used by agents) read hook JSON from stdin")
    h.add_argument("agent", choices=["claude", "codex", "cursor", "antigravity"])
    h.set_defaults(fn=cmd_hook)
    ap = sub.add_parser("approve", help="approve pending packages (opens a Windows dialog)")
    ap.add_argument("keys", nargs="*")
    ap.set_defaults(fn=cmd_approve)
    sub.add_parser("pending", help="list packages waiting for approval").set_defaults(fn=cmd_pending)
    s = sub.add_parser("scan", help="read-only scan of the whole PC (resumes where it stopped)")
    s.add_argument("--roots", nargs="*")
    s.add_argument("--restart", action="store_true")
    s.add_argument("--status", action="store_true")
    s.add_argument("--lang", choices=["tr", "en", "both"])
    s.set_defaults(fn=cmd_scan)
    i = sub.add_parser("install", help="register hooks and /pc-scan in the agents")
    i.add_argument("--agents", nargs="*", choices=["claude", "codex", "cursor", "antigravity"])
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--no-path", action="store_true")
    i.set_defaults(fn=cmd_install)
    u = sub.add_parser("uninstall", help="remove only what depbouncer added")
    u.add_argument("--dry-run", action="store_true")
    u.add_argument("--purge", action="store_true", help="also delete settings, cache and scan data")
    u.set_defaults(fn=cmd_uninstall)
    sub.add_parser("doctor", help="self-test").set_defaults(fn=cmd_doctor)
    return p


def main(argv=None):
    _utf8()
    a = build().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
