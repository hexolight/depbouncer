"""/pc-scan on a fake directory tree with fake OSV answers."""
import json
import os
from pathlib import Path

import pytest
from conftest import GHSA_MAL, MAL

from depbouncer import scan


def build_tree(root: Path):
    p = root / "proj" / "node_modules"
    p.mkdir(parents=True)
    (p / ".package-lock.json").write_text(json.dumps({"packages": {
        "node_modules/flatmap-stream": {"version": "0.1.1"}, "node_modules/lodash": {"version": "4.17.21"}}}))
    (root / "proj" / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "proj"}, "node_modules/lodash": {"version": "4.17.21"}}}))
    (root / "proj" / "package.json").write_text('{"dependencies": {"lodash": "^4"}}')
    nm = root / "app2" / "node_modules"
    (nm / "evil").mkdir(parents=True)
    (nm / "evil" / "package.json").write_text('{"name": "evil", "version": "1.0.0"}')
    (nm / "@scope" / "lib").mkdir(parents=True)
    (nm / "@scope" / "lib" / "package.json").write_text('{"name": "@scope/lib", "version": "2.0.0"}')
    sp = root / "venv" / "Lib" / "site-packages"
    (sp / "requests-2.32.3.dist-info").mkdir(parents=True)
    (sp / "requests").mkdir()
    ng = root / "home" / ".nuget" / "packages" / "newtonsoft.json" / "13.0.1"
    ng.mkdir(parents=True)
    (root / "py" ).mkdir()
    (root / "py" / "requirements.txt").write_text("namedonly\npinned==1.0\n")
    (root / "py" / ".env").write_text("SECRET=1")
    (root / "py" / "id_rsa").write_text("KEY")
    # sensitive places that must never be opened
    browser = root / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    browser.mkdir(parents=True)
    (browser / "package.json").write_text('{"name": "trap", "version": "1.0.0"}')
    (root / "x" / "User Data").mkdir(parents=True)
    (root / "x" / "User Data" / "package-lock.json").write_text("{}")
    (root / ".ssh").mkdir()
    (root / ".ssh" / "package.json").write_text("{}")


@pytest.fixture
def tree(tmp_path, monkeypatch):
    root = tmp_path / "disk"
    root.mkdir()
    build_tree(root)
    excl = [(os.path.normcase(str(root / "AppData" / "Local" / "Google")), "browser profile / tarayıcı profili")]
    monkeypatch.setattr(scan, "excluded_prefixes", lambda: excl)
    monkeypatch.setattr(scan, "low_priority", lambda: None)   # don't slow down the test runner
    opened = []
    real = scan.Scanner.read

    def spy(self, path):
        opened.append(path)
        return real(self, path)
    monkeypatch.setattr(scan.Scanner, "read", spy)
    return root, opened


def osv(fake_net):
    fake_net.osv_version[("flatmap-stream", "0.1.1")] = [GHSA_MAL]
    fake_net.vulns[GHSA_MAL["id"]] = GHSA_MAL
    fake_net.osv_version[("evil", "1.0.0")] = [MAL]
    fake_net.osv_any["namedonly"] = [{"id": "MAL-2024-9", "summary": "Malicious code in namedonly"}]


def test_full_scan(tree, fake_net):
    root, opened = tree
    osv(fake_net)
    assert scan.run(roots=[str(root)], out=lambda *_: None) == 1
    st = json.loads((scan.scan_dir() / "state.json").read_text(encoding="utf-8"))
    keys = set(st["packages"])
    assert {"npm|flatmap-stream|0.1.1", "npm|evil|1.0.0", "npm|@scope/lib|2.0.0", "pypi|requests|2.32.3",
            "nuget|newtonsoft.json|13.0.1", "pypi|pinned|1.0", "pypi|namedonly|"} <= keys
    assert "npm|trap|1.0.0" not in keys
    # never opened sensitive files or folders
    for p in opened:
        assert "User Data" not in p and ".ssh" not in p and not p.endswith((".env", "id_rsa"))
    # package.json next to a lockfile is skipped (lockfile has exact versions)
    assert not any(p.endswith(os.path.join("proj", "package.json")) for p in opened)
    f = {(x["name"], x["id"]): x for x in st["findings"]}
    assert scan.confidence(f[("flatmap-stream", GHSA_MAL["id"])])[0] == "high"
    assert scan.confidence(f[("namedonly", "MAL-2024-9")])[0] == "low"
    report = (scan.scan_dir() / "report.md").read_text(encoding="utf-8")
    assert "Taranmayanlar / Not scanned" in report and "Google" in report and "flatmap-stream" in report
    # only names/versions were sent
    for url, body in fake_net.calls:
        if body:
            for q in body.get("queries", [body]):
                assert set(q) <= {"package", "version"}


def test_resume_after_interrupt(tree, fake_net, monkeypatch):
    root, _ = tree
    osv(fake_net)
    full = scan.Scanner(scan.scan_dir() / "full.json", [str(root)])
    full.walk()
    expected = set(full.st["packages"])

    calls = {"n": 0}
    real_list = scan.Scanner.list_dir

    def flaky(self, path):
        calls["n"] += 1
        if calls["n"] == 6:
            raise KeyboardInterrupt
        return real_list(self, path)
    monkeypatch.setattr(scan.Scanner, "list_dir", flaky)
    assert scan.run(roots=[str(root)], out=lambda *_: None) == 130
    st = json.loads((scan.scan_dir() / "state.json").read_text(encoding="utf-8"))
    assert st["phase"] == "walk" and st["stack"]
    monkeypatch.setattr(scan.Scanner, "list_dir", real_list)
    scan.run(out=lambda *_: None)          # resumes, no roots needed
    st = json.loads((scan.scan_dir() / "state.json").read_text(encoding="utf-8"))
    assert st["phase"] == "done" and set(st["packages"]) == expected


def test_selftest_failure_stops_scan(tree, fake_net):
    root, _ = tree
    assert scan.run(roots=[str(root)], out=lambda *_: None) == 2     # OSV knows nothing -> stop
    assert not (scan.scan_dir() / "report.md").exists()


def test_selftest_uses_only_flatmap(fake_net):
    fake_net.osv_version[("flatmap-stream", "0.1.1")] = [GHSA_MAL]
    assert scan.selftest() == [GHSA_MAL["id"]]
    assert fake_net.calls[0][1] == {"package": {"name": "flatmap-stream", "ecosystem": "npm"}, "version": "0.1.1"}


def test_parsers():
    y = 'lodash@^4.17.0, lodash@^4.17.21:\n  version "4.17.21"\n\n"@babel/core@npm:^7.0.0":\n  version: 7.24.0\n'
    assert scan.parse_yarn_lock(y) == [("npm", "lodash", "4.17.21"), ("npm", "@babel/core", "7.24.0")]
    p = "packages:\n\n  /lodash@4.17.21:\n    resolution: x\n  '@types/node@20.1.0':\n    x: y\n  /ms/2.1.3:\n"
    assert scan.parse_pnpm_lock(p) == [("npm", "lodash", "4.17.21"), ("npm", "@types/node", "20.1.0"),
                                       ("npm", "ms", "2.1.3")]
    assert scan.dist_info_name("typing_extensions-4.12.2.dist-info") == ("pypi", "typing_extensions", "4.12.2")
    assert scan.pnpm_store_name("@babel+core@7.24.0_supports-color@9") == ("npm", "@babel/core", "7.24.0")
    assert scan.parse_toml_lock('[[package]]\nname = "rich"\nversion = "13.7.1"\n') == [("pypi", "rich", "13.7.1")]
