"""/pc-scan: read-only, low-priority, sequential, resumable scan of the PC.

It only opens a short allow-list of dependency files (lockfiles, installed
package metadata). Browser profiles, credential stores, .env files, keys and
cookies are never opened; their folders are skipped entirely. Only package
names and versions are sent to OSV. Windows Defender is not used.
"""
import json
import os
import re
import stat
import sys
import time
import tomllib
import urllib.parse
from pathlib import Path

from . import i18n, net
from .checker import OSV_NAME, is_malware, osv_query
from .config import data_dir, read_json, write_json_atomic

STATE_VERSION = 1
SAVE_EVERY_S = 3.0
MAX_FILE_BYTES = 20_000_000
MAX_DETAIL_LOOKUPS = 300

# Files we are allowed to open (lower-case base names / patterns).
ALLOWED_FILES = {"package-lock.json", "npm-shrinkwrap.json", ".package-lock.json", "yarn.lock",
                 "pnpm-lock.yaml", "bun.lock", "package.json", "poetry.lock", "uv.lock", "pipfile.lock",
                 "packages.lock.json", "project.assets.json", "packages.config", "pkg-info"}
REQ_RE = re.compile(r"^requirements[\w.-]*\.txt$")
# Defence in depth: never open these even if a rule above would allow it.
NEVER_OPEN = re.compile(r"(^\.env|\.pem$|\.key$|\.pfx$|\.p12$|^id_[a-z0-9]+|cookie|login data|"
                        r"^web data$|credential|secret|token|\.kdbx$|wallet)", re.I)
SKIP_DIR_NAMES = {".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", "user data",
                  "cookies", "inetcookies", ".git", ".hg", ".svn", "__pycache__", "$recycle.bin",
                  "system volume information", ".gnome-keyring", "keyrings"}


def excluded_prefixes():
    env = os.environ
    la, ad, pd = env.get("LOCALAPPDATA", ""), env.get("APPDATA", ""), env.get("PROGRAMDATA", "")
    win = env.get("SystemRoot", r"C:\Windows")
    rules = [
        (win, "Windows system folder / Windows sistem klasörü"),
        (os.path.join(la, "Google"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "Chromium"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "Microsoft", "Edge"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "BraveSoftware"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "Vivaldi"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "Yandex"), "browser profile / tarayıcı profili"),
        (os.path.join(la, "Mozilla"), "browser profile / tarayıcı profili"),
        (os.path.join(ad, "Mozilla"), "browser profile / tarayıcı profili"),
        (os.path.join(ad, "Opera Software"), "browser profile / tarayıcı profili"),
        (os.path.join(ad, "Microsoft", "Protect"), "credential store / kimlik deposu"),
        (os.path.join(ad, "Microsoft", "Credentials"), "credential store / kimlik deposu"),
        (os.path.join(la, "Microsoft", "Credentials"), "credential store / kimlik deposu"),
        (os.path.join(ad, "Microsoft", "Crypto"), "keys / anahtarlar"),
        (os.path.join(ad, "Microsoft", "SystemCertificates"), "keys / anahtarlar"),
        (os.path.join(la, "Microsoft", "Vault"), "credential store / kimlik deposu"),
        (os.path.join(la, "Microsoft", "Windows", "INetCookies"), "cookies / çerezler"),
        (os.path.join(ad, "Microsoft", "Windows", "Cookies"), "cookies / çerezler"),
        (os.path.join(la, "Packages"), "Store app data (may hold browser data) / Mağaza uygulama verisi"),
        (os.path.join(pd, "Microsoft", "Crypto"), "keys / anahtarlar"),
        (str(data_dir()), "depbouncer's own data / depbouncer verisi"),
    ]
    return [(os.path.normcase(os.path.abspath(p)), why) for p, why in rules if p]


def fixed_drives():
    if os.name != "nt":
        return ["/"]
    import ctypes
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    out = []
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:   # DRIVE_FIXED
                out.append(root)
    return out


def low_priority():
    try:
        if os.name == "nt":
            import ctypes
            k = ctypes.windll.kernel32
            # PROCESS_MODE_BACKGROUND_BEGIN: low CPU, I/O and memory priority
            k.SetPriorityClass(k.GetCurrentProcess(), 0x00100000)
        else:
            os.nice(10)
    except Exception:  # noqa: BLE001
        pass


def selftest():
    """flatmap-stream@0.1.1 (event-stream incident, 2018) must be reported as
    malware by OSV. If not, results cannot be trusted and the scan stops."""
    vulns = osv_query("npm", "flatmap-stream", "0.1.1")
    ids = [v["id"] for v in vulns if is_malware(v)]
    if not ids:
        raise RuntimeError("OSV did not report flatmap-stream@0.1.1 as malware")
    return ids


# -------------------------------------------------------------- file parsers
def _norm_py(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def parse_npm_lock(text):
    d = json.loads(text)
    out = []
    for key, meta in (d.get("packages") or {}).items():
        if key and isinstance(meta, dict) and meta.get("version") and not meta.get("link"):
            out.append(("npm", meta.get("name") or key.rsplit("node_modules/", 1)[-1], meta["version"]))

    def walk(deps):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                if meta.get("version") and not str(meta["version"]).startswith(("file:", "git", "http")):
                    out.append(("npm", name, meta["version"]))
                walk(meta.get("dependencies"))
    if not d.get("packages"):
        walk(d.get("dependencies"))
    return out


def parse_yarn_lock(text):
    out, names = [], []
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            m = re.match(r"^(@?[^@]+)@", first)
            names = [m.group(1)] if m else []
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and names:
                out.append(("npm", names[0], m.group(1)))
                names = []
    return out


def parse_pnpm_lock(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^  '?/?(@?[^@\s'/(]+(?:/[^@\s'/(]+)?)@([0-9][^('\s:]*)", line) or \
            re.match(r"^  '?/(@?[^/\s']+(?:/[^/\s']+)?)/([0-9][^/('\s:]*)", line)
        if m:
            out.append(("npm", m.group(1), m.group(2)))
    return out


def parse_bun_lock(text):
    return [("npm", n, v) for n, v in re.findall(r'\[\s*"(@?[^"@\s]+)@([0-9][^"]*)"', text)]


def parse_package_json(text, installed):
    d = json.loads(text)
    if not isinstance(d, dict):
        return []
    if installed:
        return [("npm", d["name"], d["version"])] if d.get("name") and d.get("version") else []
    names = set()
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        names |= set((d.get(sec) or {}).keys())
    return [("npm", n, None) for n in sorted(names)]


def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==\s*([^\s;,]+))?", line)
        if m and not line.startswith("-"):
            out.append(("pypi", m.group(1), m.group(3)))
    return out


def parse_toml_lock(text):
    d = tomllib.loads(text)
    return [("pypi", p["name"], p.get("version")) for p in d.get("package", []) if p.get("name")]


def parse_pipfile_lock(text):
    d = json.loads(text)
    out = []
    for sec in ("default", "develop"):
        for n, meta in (d.get(sec) or {}).items():
            v = (meta or {}).get("version", "")
            out.append(("pypi", n, v[2:] if v.startswith("==") else None))
    return out


def parse_pkg_info(text):
    name = ver = None
    for line in text.splitlines()[:40]:
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
    return [("pypi", name, ver)] if name else []


def parse_nuget_lock(text):
    d = json.loads(text)
    out = []
    for tfm in (d.get("dependencies") or {}).values():
        for n, meta in (tfm or {}).items():
            if (meta or {}).get("resolved") and meta.get("type") != "Project":
                out.append(("nuget", n, meta["resolved"]))
    return out


def parse_assets(text):
    d = json.loads(text)
    out = []
    for key, meta in (d.get("libraries") or {}).items():
        if (meta or {}).get("type") == "package" and "/" in key:
            n, v = key.split("/", 1)
            out.append(("nuget", n, v))
    return out


def parse_packages_config(text):
    return [("nuget", n, v) for n, v in re.findall(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text)]


def dist_info_name(dirname):
    m = re.match(r"^(.+?)-(\d[^-]*?)\.(dist-info|egg-info)$", dirname)
    return ("pypi", m.group(1), m.group(2)) if m else None


def pnpm_store_name(dirname):
    m = re.match(r"^(@?[^@]+)@([0-9][^_]*)", dirname)
    if not m:
        return None
    return ("npm", m.group(1).replace("+", "/", 1) if m.group(1).startswith("@") else m.group(1), m.group(2))


# ------------------------------------------------------------------ scanner
class Scanner:
    def __init__(self, state_path, roots=None, out=print):
        self.state_path = state_path
        self.out = out
        self.excl = excluded_prefixes()
        self.st = read_json(state_path, None)
        if not self.st or self.st.get("version") != STATE_VERSION or self.st.get("phase") == "done" and roots:
            self.st = None
        if self.st is None:
            roots = roots or fixed_drives()
            self.st = {"version": STATE_VERSION, "phase": "walk", "roots": roots,
                       "stack": [os.path.abspath(r) for r in reversed(roots)], "packages": {},
                       "dirs": 0, "files": 0, "denied": [], "denied_count": 0, "excluded": [],
                       "errors": [], "query_pos": 0, "raw_hits": [], "other_vulns": 0,
                       "started": time.strftime("%Y-%m-%d %H:%M:%S"), "updated": None}
        self._last_save = time.monotonic()

    # -- state
    def save(self, force=False):
        if force or time.monotonic() - self._last_save > SAVE_EVERY_S:
            self.st["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            write_json_atomic(self.state_path, self.st)
            self._last_save = time.monotonic()

    def add(self, eco, name, version, path, source):
        if not name:
            return
        n = _norm_py(name) if eco == "pypi" else name.lower() if eco == "nuget" else name
        key = f"{eco}|{n}|{version or ''}"
        rec = self.st["packages"].setdefault(key, {"eco": eco, "name": name, "version": version,
                                                   "paths": [], "source": source})
        if len(rec["paths"]) < 3 and path not in rec["paths"]:
            rec["paths"].append(path)
        if source == "installed":
            rec["source"] = "installed"

    def note_denied(self, path, err):
        self.st["denied_count"] += 1
        if len(self.st["denied"]) < 300:
            self.st["denied"].append(f"{path} ({type(err).__name__})")

    def is_excluded(self, path):
        p = os.path.normcase(os.path.abspath(path))
        for pref, why in self.excl:
            if p == pref or p.startswith(pref + os.sep):
                return why
        if os.path.basename(p) in SKIP_DIR_NAMES:
            return "sensitive or irrelevant folder name / hassas ya da ilgisiz klasör adı"
        return None

    # -- reading
    def read(self, path):
        base = os.path.basename(path)
        if NEVER_OPEN.search(base):
            raise PermissionError("refused by depbouncer policy")
        st = os.stat(path)
        if st.st_size > MAX_FILE_BYTES:
            raise ValueError("file too large")
        self.st["files"] += 1
        with open(path, "rb") as f:       # read-only
            return f.read().decode("utf-8-sig", errors="replace")

    def parse_file(self, path, in_node_modules=False):
        b = os.path.basename(path).lower()
        try:
            if b in ("package-lock.json", "npm-shrinkwrap.json", ".package-lock.json"):
                items, src = parse_npm_lock(self.read(path)), "installed" if b == ".package-lock.json" else "lockfile"
            elif b == "yarn.lock":
                items, src = parse_yarn_lock(self.read(path)), "lockfile"
            elif b == "pnpm-lock.yaml":
                items, src = parse_pnpm_lock(self.read(path)), "lockfile"
            elif b == "bun.lock":
                items, src = parse_bun_lock(self.read(path)), "lockfile"
            elif b == "package.json":
                items, src = parse_package_json(self.read(path), in_node_modules), \
                    "installed" if in_node_modules else "manifest"
            elif REQ_RE.match(b):
                items, src = parse_requirements(self.read(path)), "manifest"
            elif b in ("poetry.lock", "uv.lock"):
                items, src = parse_toml_lock(self.read(path)), "lockfile"
            elif b == "pipfile.lock":
                items, src = parse_pipfile_lock(self.read(path)), "lockfile"
            elif b == "pkg-info":
                items, src = parse_pkg_info(self.read(path)), "installed"
            elif b == "packages.lock.json":
                items, src = parse_nuget_lock(self.read(path)), "lockfile"
            elif b == "project.assets.json":
                items, src = parse_assets(self.read(path)), "lockfile"
            elif b == "packages.config":
                items, src = parse_packages_config(self.read(path)), "manifest"
            else:
                return
        except (OSError, PermissionError) as e:
            self.note_denied(path, e)
            return
        except Exception as e:  # noqa: BLE001 - a broken file is reported, never fatal
            if len(self.st["errors"]) < 300:
                self.st["errors"].append(f"{path}: {type(e).__name__}")
            return
        for eco, n, v in items:
            self.add(eco, n, v, path, src)

    # -- walking
    def list_dir(self, path):
        try:
            with os.scandir(path) as it:
                return sorted(it, key=lambda e: e.name.lower())
        except OSError as e:
            self.note_denied(path, e)
            return None

    @staticmethod
    def is_real_dir(entry):
        try:
            if entry.is_symlink():
                return False
            st_ = entry.stat(follow_symlinks=False)
            attrs = getattr(st_, "st_file_attributes", 0)
            if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                return False        # junctions / OneDrive placeholders: skipped
            return stat.S_ISDIR(st_.st_mode)
        except OSError:
            return False

    def handle_node_modules(self, path):
        entries = self.list_dir(path)
        if entries is None:
            return
        names = {e.name for e in entries}
        if ".package-lock.json" in names:
            self.parse_file(os.path.join(path, ".package-lock.json"))
            return
        for e in entries:
            if e.name == ".pnpm" and self.is_real_dir(e):
                sub = self.list_dir(e.path) or []
                for s in sub:
                    r = pnpm_store_name(s.name)
                    if r:
                        self.add(*r, s.path, "installed")
                continue
            if e.name.startswith(".") or not self.is_real_dir(e):
                continue
            pkgs = [e]
            if e.name.startswith("@"):
                pkgs = [s for s in (self.list_dir(e.path) or []) if self.is_real_dir(s)]
            for p in pkgs:
                pj = os.path.join(p.path, "package.json")
                if os.path.isfile(pj):
                    self.parse_file(pj, in_node_modules=True)
                nested = os.path.join(p.path, "node_modules")
                if os.path.isdir(nested):
                    self.st["stack"].append(nested)

    def handle_site_packages(self, path):
        for e in self.list_dir(path) or []:
            r = dist_info_name(e.name) if e.name.endswith((".dist-info", ".egg-info")) else None
            if r:
                self.add(*r, e.path, "installed")
            elif e.name.endswith(".egg-info") and self.is_real_dir(e):
                self.parse_file(os.path.join(e.path, "PKG-INFO"))

    def handle_nuget_cache(self, path):
        for e in self.list_dir(path) or []:
            if self.is_real_dir(e):
                for v in self.list_dir(e.path) or []:
                    if self.is_real_dir(v):
                        self.add("nuget", e.name, v.name, v.path, "installed")

    def walk(self):
        stack = self.st["stack"]
        while stack:
            path = stack.pop()
            why = self.is_excluded(path)
            if why:
                if len(self.st["excluded"]) < 500:
                    self.st["excluded"].append(f"{path} — {why}")
                continue
            self.st["dirs"] += 1
            low = os.path.basename(path).lower()
            parent = os.path.basename(os.path.dirname(path)).lower()
            if low == "node_modules":
                self.handle_node_modules(path)
            elif low in ("site-packages", "dist-packages"):
                self.handle_site_packages(path)
            elif low == "packages" and parent == ".nuget":
                self.handle_nuget_cache(path)
            else:
                entries = self.list_dir(path)
                if entries is not None:
                    names = {e.name.lower() for e in entries}
                    has_lock = bool(names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
                                             "npm-shrinkwrap.json"})
                    subdirs = []
                    for e in entries:
                        if self.is_real_dir(e):
                            subdirs.append(e.path)
                            continue
                        b = e.name.lower()
                        if b == "package.json" and has_lock:
                            continue        # the lockfile has exact versions
                        if b in ALLOWED_FILES or REQ_RE.match(b):
                            self.parse_file(e.path)
                    stack.extend(reversed(subdirs))
            if self.st["dirs"] % 200 == 0:
                time.sleep(0.005)          # stay gentle on the disk
            self.save()
        self.st["phase"] = "query"
        self.save(force=True)

    # -- querying
    def query(self):
        keys = sorted(self.st["packages"])
        pos = self.st["query_pos"]
        while pos < len(keys):
            chunk = keys[pos:pos + 500]
            qs = []
            for k in chunk:
                p = self.st["packages"][k]
                q = {"package": {"name": p["name"], "ecosystem": OSV_NAME[p["eco"]]}}
                if p["version"]:
                    q["version"] = p["version"]
                qs.append(q)
            res = net.fetch("https://api.osv.dev/v1/querybatch", {"queries": qs}).get("results", [])
            if len(res) != len(chunk):
                raise RuntimeError("OSV batch answer incomplete")
            for k, r in zip(chunk, res):
                for v in r.get("vulns") or []:
                    self.st["raw_hits"].append([k, v.get("id", "")])
            pos += len(chunk)
            self.st["query_pos"] = pos
            self.save(force=True)
            time.sleep(0.2)
        self.st["phase"] = "details"
        self.save(force=True)

    def details(self):
        findings, other, looked = [], 0, 0
        cache = {}
        for key, vid in self.st["raw_hits"]:
            mal_by_id = vid.startswith("MAL-")
            if not mal_by_id and looked >= MAX_DETAIL_LOOKUPS:
                other += 1
                continue
            if vid not in cache:
                try:
                    cache[vid] = net.fetch("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid))
                except Exception:  # noqa: BLE001
                    cache[vid] = {"id": vid, "summary": "(details unavailable)"}
                if not mal_by_id:
                    looked += 1
            v = cache[vid]
            if mal_by_id or is_malware(v):
                p = self.st["packages"][key]
                findings.append({"eco": p["eco"], "name": p["name"], "version": p["version"], "id": vid,
                                 "summary": v.get("summary", ""), "aliases": v.get("aliases", []),
                                 "paths": p["paths"], "source": p["source"],
                                 "withdrawn": bool(v.get("withdrawn")),
                                 "link": f"https://osv.dev/vulnerability/{vid}"})
            else:
                other += 1
        self.st["findings"] = findings
        self.st["other_vulns"] = other
        self.st["phase"] = "done"
        self.st["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.save(force=True)


def confidence(f):
    """How likely is this a real hit? Returns (level, tr, en)."""
    if f["version"] is None:
        return ("low", "Sürüm bilinmiyor (yalnızca ad, bildirim dosyasından): OSV kaydı bu adın bazı sürümlerini "
                       "kapsıyor; kurulu sürüm temiz olabilir. Kilit dosyası veya kurulu sürümle doğrulayın.",
                "Version unknown (name only, from a manifest): the OSV record covers some versions of this "
                "name; the installed one may be clean. Confirm with a lockfile or the installed version.")
    if f["source"] == "installed":
        return ("high", "Kurulu paket ve OSV bu tam sürümü zararlı olarak listeliyor.",
                "Installed package and OSV lists this exact version as malicious.")
    return ("medium", "Kilit/bildirim dosyasında bu tam sürüm var; paket şu an kurulu olmayabilir "
                      "(eski bir kilit dosyası olabilir).",
            "This exact version is in a lock/manifest file; it may not be installed right now "
            "(could be an old lockfile).")


NOT_COVERED = [
    ("Ağ sürücüleri, çıkarılabilir diskler, \\\\wsl$ dağıtımları, Docker imajları ve sanal makineler",
     "Network drives, removable disks, \\\\wsl$ distributions, Docker images and virtual machines"),
    ("conda paketleri (conda-meta), Go/Rust/Java/Ruby/PHP paketleri, tarayıcı eklentileri, VS Code eklentileri",
     "conda packages (conda-meta), Go/Rust/Java/Ruby/PHP packages, browser and VS Code extensions"),
    ("Sembolik bağlar ve bağlantı noktaları (junction) izlenmez; OneDrive'da yalnızca bulutta olan dosyalar açılmaz",
     "Symlinks and junctions are not followed; OneDrive cloud-only files are not opened"),
    ("OSV'de kaydı olmayan yeni zararlılar bulunamaz; bu tarama virüs taraması değildir",
     "New malware without an OSV record cannot be found; this is not an antivirus scan"),
]


def write_report(st, lang, out_dir):
    f_list = st.get("findings", [])
    lines = ["# depbouncer /pc-scan", "",
             f"- Başlangıç / Started: {st.get('started')}  ·  Bitiş / Finished: {st.get('finished')}",
             f"- Kökler / Roots: {', '.join(st['roots'])}",
             f"- Taranan klasör / Folders: {st['dirs']}  ·  Okunan dosya / Files read: {st['files']}",
             f"- Bulunan paket kaydı / Package records: {len(st['packages'])}",
             f"- OSV öz-sınaması / self-test: {', '.join(st.get('selftest', []))}",
             f"- Zararlı bulgu / Malware findings: **{len(f_list)}**",
             f"- Diğer güvenlik bildirimleri (zararlı değil) / Other advisories (not malware): {st.get('other_vulns', 0)}",
             ""]
    lines.append("## Bulgular / Findings")
    if not f_list:
        lines.append("OSV'de zararlı kaydı olan paket bulunmadı. Bu, bilgisayarın temiz olduğu anlamına gelmez.  ")
        lines.append("No package with an OSV malware record was found. This does not mean the PC is clean.")
    for f in f_list:
        lvl, tr, en = confidence(f)
        lines += [f"### {f['eco']} {f['name']}@{f['version'] or '?'} — {f['id']}",
                  f"- Özet / Summary: {f['summary']}",
                  f"- Kanıt / Evidence: {f['link']}" + (f" (aliases: {', '.join(f['aliases'])})" if f['aliases'] else ""),
                  "- Dosyalar / Files: " + "; ".join(f["paths"]),
                  f"- Yanlış alarm olasılığı / False-alarm likelihood: güven/confidence **{lvl}** — {tr} / {en}", ""]
    lines += ["## Yanlış alarm nasıl değerlendirildi / How false alarms are judged",
              "- Yalnızca OSV'de MAL- kimliği olan ya da özeti 'malicious/malware' diyen ve geri çekilmemiş kayıtlar "
              "bulgu sayılır. / Only non-withdrawn OSV records with a MAL- id or a 'malicious/malware' summary count.",
              "- Tam sürüm eşleşmesi OSV'nin kendi sürüm aralığı hesabıyla yapılır. / Exact version matching uses "
              "OSV's own affected-range logic.",
              "- Kurulu > kilit dosyası > yalnızca ad sırasıyla güven azalır. / Confidence drops from installed to "
              "lockfile to name-only.", ""]
    lines.append("## Taranmayanlar / Not scanned")
    for tr, en in NOT_COVERED:
        lines.append(f"- {tr} / {en}")
    lines.append(f"- Hariç tutulan klasörler / Excluded folders ({len(st['excluded'])}):")
    lines += [f"  - {x}" for x in st["excluded"][:200]]
    lines.append(f"- Erişilemeyen yerler / Access denied or unreadable: {st['denied_count']}")
    lines += [f"  - {x}" for x in st["denied"][:100]]
    if st["errors"]:
        lines.append(f"- Okunamayan/bozuk dosyalar / Unparseable files: {len(st['errors'])}")
        lines += [f"  - {x}" for x in st["errors"][:100]]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json_atomic(out_dir / "report.json", {k: st.get(k) for k in (
        "started", "finished", "roots", "dirs", "files", "findings", "other_vulns", "excluded",
        "denied", "denied_count", "errors", "selftest")})
    return out_dir / "report.md"


def scan_dir():
    return data_dir() / "scan"


def run(roots=None, restart=False, lang=None, out=print):
    sd = scan_dir()
    state_path = sd / "state.json"
    if restart and state_path.exists():
        state_path.unlink()
    low_priority()
    try:
        ids = selftest()
    except Exception as e:  # noqa: BLE001
        out(f"OSV öz-sınaması başarısız, tarama durduruldu / OSV self-test failed, scan stopped: {e}")
        return 2
    sc = Scanner(state_path, roots, out)
    sc.st["selftest"] = [f"flatmap-stream@0.1.1 -> {', '.join(ids)}"]
    if sc.st["phase"] == "done":
        out("Önceki tarama tamamlanmış; yeniden başlatmak için --restart / Previous scan finished; use --restart.")
        out(str(sd / "report.md"))
        return 0
    out(f"Tarama {'sürüyor' if sc.st['dirs'] else 'başladı'} / Scan {'resuming' if sc.st['dirs'] else 'started'}: "
        f"{', '.join(sc.st['roots'])}")
    try:
        if sc.st["phase"] == "walk":
            sc.walk()
        if sc.st["phase"] == "query":
            sc.query()
        if sc.st["phase"] == "details":
            sc.details()
    except KeyboardInterrupt:
        sc.save(force=True)
        out("Durduruldu; ilerleme kaydedildi. Sürdürmek için tekrar çalıştırın. / Stopped; progress saved.")
        return 130
    except Exception as e:  # noqa: BLE001
        sc.save(force=True)
        out(f"Hata, ilerleme kaydedildi / Error, progress saved: {e}")
        return 1
    rep = write_report(sc.st, lang or "both", sd)
    out(f"Bitti / Done: {len(sc.st.get('findings', []))} bulgu/findings -> {rep}")
    return 1 if sc.st.get("findings") else 0


def status(out=print):
    st = read_json(scan_dir() / "state.json", None)
    if not st:
        out("Tarama yok / No scan yet.")
        return 0
    out(f"Aşama/phase: {st['phase']}  klasör/folders: {st['dirs']}  dosya/files: {st['files']}  "
        f"paket/packages: {len(st['packages'])}  bekleyen/queued dirs: {len(st['stack'])}  "
        f"sorgulanan/queried: {st['query_pos']}  güncelleme/updated: {st.get('updated')}")
    if st["phase"] == "done":
        out(f"Bulgu/findings: {len(st.get('findings', []))} -> {scan_dir() / 'report.md'}")
    return 0
