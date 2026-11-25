"""Agent-independent decision: request -> PASS / ASK / BLOCK with reasons."""
import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import approvals, checker, commands, i18n, manifests, transitive
from .checker import ORDER, Result
from .config import Config, data_dir, read_json, write_json_atomic

MAX_INTENTS = 150
CACHE_TTL = {"PASS": 6 * 3600, "ASK": 3600, "BLOCK": 3600}


@dataclass
class Edit:
    path: str
    old: str | None
    new: str | None        # None: the edit could not be reconstructed


@dataclass
class Request:
    agent: str
    command: str | None = None
    cwd: str | None = None
    edits: list = field(default_factory=list)
    permission_mode: str | None = None
    native_ask: bool = False     # the agent's own "ask" really prompts the user here


@dataclass
class Item:
    label: str
    result: Result
    key: str
    approved: bool = False


@dataclass
class Outcome:
    verdict: str
    items: list
    relevant: bool

    def ask_keys(self):
        return [i.key for i in self.items if i.result.verdict == "ASK" and not i.approved]


# ------------------------------------------------------------------- tamper
def protected_paths():
    home = Path.home()
    return [data_dir(), home / ".claude" / "settings.json", home / ".claude" / "settings.local.json",
            home / ".codex" / "hooks.json", home / ".codex" / "config.toml", home / ".cursor" / "hooks.json",
            home / ".gemini" / "config" / "hooks.json"]


_PROTECTED_NAMES = re.compile(
    r"([\\/]\.claude[\\/]settings(\.local)?\.json|[\\/]\.codex[\\/](hooks\.json|config\.toml)|"
    r"[\\/]\.cursor[\\/]hooks\.json|[\\/]\.gemini[\\/]config[\\/]hooks\.json|[\\/]\.agents[\\/]hooks\.json|"
    r"appdata[\\/]local[\\/]depbouncer\b|localappdata%?[\\/]depbouncer\b)", re.I)
_WRITE_VERB = re.compile(
    r"(>|\b(set-content|add-content|out-file|sc|ac|tee|sed|rm|del|erase|remove-item|ri|rd|rmdir|mv|move|"
    r"move-item|cp|copy|copy-item|cpi|xcopy|robocopy|new-item|ni|python\d*|py|node|perl|ruby|jq|echo|"
    r"writealltext|writealllines|icacls|attrib|takeown|reg)\b)", re.I)
_APPROVE_CMD = re.compile(r"\bdepbouncer(\.cmd|\.exe|\.py)?[\"']?\s+(approve|uninstall|install)\b|"
                          r"depbouncer\S*[\\/](uninstall|install)\.ps1|\b(approvals|pending)\.json\b", re.I)


def _strip_depbouncer_cli(cmd):
    """The read-only CLI calls (scan, check, status, doctor) are fine: remove
    them before looking for write verbs, so the launcher path itself is ignored."""
    return re.sub(r"[\"']?[^\s\"']*depbouncer(\.cmd)?[\"']?\s+(scan|check|status|doctor|version|pending)\b[^|;&>]*",
                  "", cmd, flags=re.I)


def _is_protected_file(path):
    try:
        p = Path(path).expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    for prot in protected_paths():
        try:
            prot = prot.resolve()
        except OSError:
            continue
        if p == prot or prot in p.parents:
            return True
    norm = "/" + str(p).replace("\\", "/")
    return bool(_PROTECTED_NAMES.search(norm)) and not norm.lower().endswith((".md",))


_SCRIPT_REF = re.compile(r"[^\s\"'&;|]*(un)?install\.ps1", re.I)


def _is_our_script(cmd, cwd):
    """An install/uninstall .ps1 that is depbouncer's own (e.g. run from a clone of the repo)."""
    for m in _SCRIPT_REF.finditer(cmd):
        p = os.path.expandvars(os.path.expanduser(m.group(0))).replace("\\", os.sep)
        if not os.path.isabs(p):
            p = os.path.join(cwd or os.getcwd(), p)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                if "depbouncer" in f.read(20000).lower():
                    return True
        except OSError:
            continue
    return False


def tamper_reason(req):
    if req.command:
        c = req.command
        if _APPROVE_CMD.search(c):
            return "depbouncer approve/install/uninstall"
        if _is_our_script(c, req.cwd):
            return "depbouncer install/uninstall script"
        expanded = os.path.expandvars(c.replace("$env:LOCALAPPDATA", os.environ.get("LOCALAPPDATA", "")))
        flat = expanded.replace("/", "\\").lower()
        if (_PROTECTED_NAMES.search(c) or _PROTECTED_NAMES.search(expanded) or str(data_dir()).replace("/", "\\").lower() in flat) \
                and _WRITE_VERB.search(_strip_depbouncer_cli(expanded)):
            return "write to protected file"
    for e in req.edits:
        if _is_protected_file(e.path):
            return os.path.basename(e.path)
    return None


# ------------------------------------------------------------------- intents
def _read(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    except OSError:
        return None


def collect(req):
    intents = []
    if req.command:
        for it in commands.parse(req.command, req.cwd):
            if it.bare:
                found = False
                for mf in manifests.find_manifests(req.cwd or os.getcwd(), it.bare):
                    text = _read(mf)
                    if text is None:
                        continue
                    found = True
                    try:
                        sub = manifests.all_intents(mf, text)
                    except manifests.Unparseable:
                        sub = [commands.Intent(problem=("edit_unreadable", {"path": mf}), origin=mf)]
                    for s in sub:
                        if it.problem and not s.problem:
                            s.problem = it.problem
                    intents += sub
                if not found and it.problem:
                    intents.append(it)
            elif it.req_file:
                text = _read(it.req_file)
                if text is None:
                    intents.append(commands.Intent(problem=("edit_unreadable", {"path": it.req_file}),
                                                   origin=it.req_file))
                    continue
                sub = [i for k, v in manifests._req_lines(text).items() for i in [manifests.to_intent(k, v)] if i]
                for s in sub:
                    if it.problem and not s.problem:
                        s.problem = it.problem
                intents += sub
            else:
                intents.append(it)
    for e in req.edits:
        if manifests.kind(e.path) is None:
            continue
        if e.new is None:
            intents.append(commands.Intent(problem=("edit_unreadable", {"path": os.path.basename(e.path)}),
                                           origin=e.path))
            continue
        try:
            intents += manifests.diff(e.path, e.old, e.new)
        except manifests.Unparseable:
            intents.append(commands.Intent(problem=("edit_unreadable", {"path": os.path.basename(e.path)}),
                                           origin=e.path))
    seen, out = set(), []
    for it in intents:
        sig = (it.eco, (it.name or "").lower(), it.spec, it.problem and it.problem[0], it.origin if it.problem else "")
        if sig not in seen:
            seen.add(sig)
            out.append(it)
    return out


# --------------------------------------------------------------------- cache
def _cache_key(it):
    return f"{it.eco}:{(it.name or '').lower()}@{it.spec or ''}"


def _cache_get(key):
    c = read_json(data_dir() / "cache.json", {}).get(key)
    if not c or time.time() - c.get("ts", 0) > CACHE_TTL.get(c.get("verdict"), 0):
        return None
    r = Result(c["verdict"], [tuple(x) for x in c["reasons"]], [tuple(x) for x in c["facts"]], c.get("version"))
    r.facts.append(("fact_cached", {}))
    return r


def _cache_put(key, r):
    path = data_dir() / "cache.json"
    c = read_json(path, {})
    now = time.time()
    c = {k: v for k, v in c.items() if now - v.get("ts", 0) < 24 * 3600}
    c[key] = {"verdict": r.verdict, "reasons": r.reasons, "facts": [f for f in r.facts if f[0] != "fact_cached"],
              "version": r.version, "ts": now}
    try:
        write_json_atomic(path, c)
    except OSError:
        pass


def approval_key(it, r):
    if it.problem or not it.eco:
        return "raw:" + hashlib.sha256((it.origin or "").encode()).hexdigest()[:16]
    name = it.name.lower()
    if it.eco == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return f"{it.eco}:{name}@{r.version or it.spec or 'latest'}"


def label(it, r=None):
    if it.problem or not it.eco:
        return it.origin[:100] or "?"
    v = (r.version if r and r.version else None) or it.spec or "latest"
    return f"{it.eco} {it.name}@{v}"


def check_one(it, cfg, deadline, use_cache=True):
    if it.problem:
        return Result("ASK", [it.problem])
    if cfg.is_private(it.eco, it.name):
        return Result("PASS" if cfg.private_result == "pass" else "ASK", [("private_pkg", {})])
    key = _cache_key(it)
    if use_cache:
        hit = _cache_get(key)
        if hit:
            return hit
    if deadline is None:
        deadline = time.monotonic() + 120
    r = checker.check(it.eco, it.name, it.spec, cfg, deadline, transitive_fn=transitive.check)
    if use_cache:
        _cache_put(key, r)
    return r


def evaluate(req, cfg: Config, deadline=None):
    t = tamper_reason(req)
    if t:
        return Outcome("BLOCK", [Item("depbouncer", Result("BLOCK", [("tamper", {"what": t})]), "tamper")], True)
    intents = collect(req)
    if not intents:
        return Outcome("PASS", [], False)
    if len(intents) > MAX_INTENTS:
        return Outcome("ASK", [Item("…", Result("ASK", [("too_many", {"n": len(intents)})]),
                                    "raw:too-many-" + str(len(intents)))], True)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda i: check_one(i, cfg, deadline), intents))
    items = []
    for it, r in zip(intents, results):
        key = approval_key(it, r)
        item = Item(label(it, r), r, key)
        if r.verdict == "ASK" and approvals.is_approved(key):
            item.approved = True
        items.append(item)
    worst = "PASS"
    for i in items:
        v = "PASS" if i.approved else i.result.verdict
        worst = ORDER[max(ORDER.index(worst), ORDER.index(v))]
    return Outcome(worst, items, True)


def finalize(out: Outcome, req: Request, cfg: Config, deny_instead_of_ask: bool):
    """Side effects after a decision: consume used approvals, record pending."""
    if out.verdict == "PASS":
        for i in out.items:
            if i.approved:
                approvals.consume(i.key)
    elif out.verdict == "ASK" and deny_instead_of_ask:
        for i in out.items:
            if i.result.verdict == "ASK" and not i.approved:
                approvals.add_pending(i.key, i.label, reasons_text(i.result, cfg.lang), req.agent)
    log(req, out)


def reasons_text(r, lang):
    return "; ".join(i18n.text(c, p, lang) for c, p in r.reasons)


def render(out: Outcome, cfg: Config, approval_hint: bool):
    lang = cfg.lang
    lines = [f"depbouncer: {i18n.pick(i18n.VERDICT[out.verdict], lang)}"]
    for i in out.items:
        v = "PASS" if i.approved else i.result.verdict
        parts = [i18n.text(c, p, lang) for c, p in i.result.reasons]
        facts = [i18n.text(c, p, lang) for c, p in i.result.facts]
        if i.approved:
            facts.append(i18n.text("fact_approved", {}, lang))
        line = f"- {i.label}: {i18n.pick(i18n.VERDICT[v], lang)}"
        if parts:
            line += " — " + "; ".join(parts)
        if facts:
            line += f" ({'; '.join(facts)})"
        lines.append(line)
    if out.verdict == "ASK" and approval_hint:
        lines.append(i18n.pick(i18n.HOW_TO_APPROVE, lang))
        lines.append(i18n.pick(i18n.AGENT_NOTE, lang))
    if out.verdict != "PASS":
        lines.append({"tr": "Not: GEÇTİ bir paketin güvenli olduğu anlamına gelmez.",
                      "en": "Note: PASS never means a package is safe."}.get(lang,
                     "Not/Note: GEÇTİ/PASS bir paketin güvenli olduğu anlamına gelmez / never means safe."))
    return "\n".join(lines)


def log(req, out):
    """Local log with package names only (no file contents)."""
    try:
        path = data_dir() / "log.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 5_000_000:
            path.replace(path.with_suffix(".old.jsonl"))
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "agent": req.agent, "verdict": out.verdict,
               "items": [{"pkg": i.label, "verdict": i.result.verdict, "approved": i.approved,
                          "reasons": [c for c, _ in i.result.reasons]} for i in out.items]}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
