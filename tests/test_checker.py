"""Every check of the original check_package.py, plus the new ones."""
from urllib.parse import urlsplit

from conftest import ADV, GHSA_MAL, MAL, codes

from depbouncer import checker, net


def test_npm_pass(fake_net, cfg):
    fake_net.npm("goodpkg", ["1.0.0", "1.2.0"])
    r = checker.check("npm", "goodpkg", None, cfg)
    assert r.verdict == "PASS" and r.version == "1.2.0"


def test_not_found_is_block(fake_net, cfg):
    r = checker.check("npm", "hallucinated-pkg-xyz", None, cfg)
    assert r.verdict == "BLOCK" and codes(r) == ["not_found"]


def test_malware_this_version_block(fake_net, cfg):
    fake_net.npm("evil", ["1.0.0"])
    fake_net.osv_version[("evil", "1.0.0")] = [MAL]
    fake_net.osv_any["evil"] = [MAL]
    r = checker.check("npm", "evil", "1.0.0", cfg)
    assert r.verdict == "BLOCK" and "known_malware" in codes(r)


def test_ghsa_malware_summary_block(fake_net, cfg):
    fake_net.npm("flatmap-stream", ["0.1.0", "0.1.1"])
    fake_net.osv_version[("flatmap-stream", "0.1.1")] = [GHSA_MAL]
    r = checker.check("npm", "flatmap-stream", "0.1.1", cfg)
    assert r.verdict == "BLOCK"


def test_withdrawn_malware_not_counted(fake_net, cfg):
    fake_net.npm("okpkg")
    fake_net.osv_version[("okpkg", "1.0.0")] = [{**MAL, "withdrawn": "2025-01-01"}]
    r = checker.check("npm", "okpkg", None, cfg)
    assert "known_malware" not in codes(r)


def test_removed_version_still_checked_in_osv(fake_net, cfg):
    fake_net.npm("flatmap-stream", ["0.0.1-security"])
    fake_net.osv_version[("flatmap-stream", "0.1.1")] = [GHSA_MAL]
    r = checker.check("npm", "flatmap-stream", "0.1.1", cfg)
    assert r.verdict == "BLOCK"


def test_malware_other_version_ask(fake_net, cfg):
    fake_net.npm("mixed", ["1.0.0", "2.0.0"])
    fake_net.osv_any["mixed"] = [MAL]
    r = checker.check("npm", "mixed", "2.0.0", cfg)
    assert r.verdict == "ASK" and "malware_other_versions" in codes(r)


def test_advisories_ask(fake_net, cfg):
    fake_net.npm("vuln")
    fake_net.osv_version[("vuln", "1.0.0")] = [ADV]
    assert "advisories" in codes(checker.check("npm", "vuln", None, cfg))


def test_new_package_ask(fake_net, cfg):
    fake_net.npm("fresh", created_days=5)
    r = checker.check("npm", "fresh", None, cfg)
    assert r.verdict == "ASK" and "new_package" in codes(r)


def test_few_downloads_ask(fake_net, cfg):
    fake_net.npm("lonely", downloads=12)
    assert "few_downloads" in codes(checker.check("npm", "lonely", None, cfg))


def test_install_script_ask(fake_net, cfg):
    fake_net.npm("scripty", scripts={"postinstall": "node x.js"})
    assert "install_script" in codes(checker.check("npm", "scripty", None, cfg))


def test_deprecated_ask(fake_net, cfg):
    fake_net.npm("old", deprecated="use new")
    assert "deprecated" in codes(checker.check("npm", "old", None, cfg))


def test_security_placeholder_block(fake_net, cfg):
    fake_net.npm("gone", ["0.0.1-security"])
    assert checker.check("npm", "gone", None, cfg).verdict == "BLOCK"


def test_no_repo_ask(fake_net, cfg):
    fake_net.npm("norepo", repo=False)
    assert "no_repo" in codes(checker.check("npm", "norepo", None, cfg))


def test_osv_down_is_ask_never_pass(fake_net, cfg):
    fake_net.npm("goodpkg")
    fake_net.osv_down = True
    r = checker.check("npm", "goodpkg", None, cfg)
    assert r.verdict == "ASK" and "osv_unreachable" in codes(r)


def test_downloads_unavailable_ask(fake_net, cfg):
    fake_net.npm("goodpkg")
    fake_net.routes["https://api.npmjs.org/downloads/point/last-week/goodpkg"] = net.http_error("x", 429)
    assert "downloads_unavailable" in codes(checker.check("npm", "goodpkg", None, cfg))


def test_registry_error_ask(fake_net, cfg):
    fake_net.routes["https://registry.npmjs.org/flaky"] = net.http_error("x", 503)
    r = checker.check("npm", "flaky", None, cfg)
    assert r.verdict == "ASK" and codes(r) == ["http_error"]


def test_range_resolves_highest(fake_net, cfg):
    fake_net.npm("ranged", ["4.16.0", "4.17.1", "4.17.21", "5.0.0", "4.18.0-beta.1"])
    assert checker.check("npm", "ranged", "^4.17.0", cfg).version == "4.17.21"
    assert checker.check("npm", "ranged", "~4.16", cfg).version == "4.16.0"


def test_unresolvable_range_ask(fake_net, cfg):
    fake_net.npm("ranged", ["1.0.0"])
    assert codes(checker.check("npm", "ranged", ">=9", cfg)) == ["range_unresolved"]


def test_bad_name_no_network(fake_net, cfg):
    r = checker.check("npm", "bad name;rm -rf", None, cfg)
    assert r.verdict == "ASK" and fake_net.calls == []


def test_typosquat_ask(fake_net, cfg):
    fake_net.npm("expresss", downloads=300)
    r = checker.check("npm", "expresss", None, cfg)
    assert "typosquat" in codes(r)


def test_popular_lookalike_not_flagged(fake_net, cfg):
    fake_net.npm("preactx", downloads=5_000_000)      # widely used: not a suspect
    assert "typosquat" not in codes(checker.check("npm", "preactx", None, cfg))


def test_pypi_pass_and_spec(fake_net, cfg):
    fake_net.pypi("goodlib", ["1.0.0", "2.0.0", "2.5.1"])
    assert checker.check("pypi", "goodlib", None, cfg).verdict == "PASS"
    assert checker.check("pypi", "goodlib", ">=2,<2.5", cfg).version == "2.0.0"
    assert checker.check("pypi", "goodlib", "==1.0.0", cfg).version == "1.0.0"


def test_pypi_sdist_only_and_yanked(fake_net, cfg):
    fake_net.pypi("srcpkg", ["1.0"], sdist_only=True, yanked=("1.0",))
    c = codes(checker.check("pypi", "srcpkg", "==1.0", cfg))
    assert "sdist_only" in c and "yanked" in c


def test_nuget_unverified_and_unlisted(fake_net, cfg):
    fake_net.nuget("Some.Lib", ["1.0.0"], verified=False)
    assert "nuget_unverified" in codes(checker.check("nuget", "Some.Lib", None, cfg))
    fake_net.nuget("Hidden.Lib", ["1.0.0"], listed=False)
    assert "nuget_unlisted" in codes(checker.check("nuget", "Hidden.Lib", None, cfg))


def test_nuget_lowest_matching(fake_net, cfg):
    fake_net.nuget("Range.Lib", ["1.0.0", "1.2.0", "2.0.0"])
    assert checker.check("nuget", "Range.Lib", "[1.1.0, 2.0.0)", cfg).version == "1.2.0"
    assert checker.check("nuget", "Range.Lib", "1.1", cfg).version == "1.2.0"


def test_only_names_and_versions_leave_the_machine(fake_net, cfg):
    fake_net.npm("goodpkg")
    fake_net.pypi("goodlib")
    checker.check("npm", "goodpkg", None, cfg)
    checker.check("pypi", "goodlib", None, cfg)
    for url, body in fake_net.calls:
        assert urlsplit(url).hostname in net.ALLOWED_HOSTS
        if body is not None:
            assert set(body) <= {"package", "version"}
            assert set(body["package"]) == {"name", "ecosystem"}


def test_non_allowed_host_refused():
    import pytest
    with pytest.raises(net.BlockedHost):
        net.fetch("https://evil.example.com/x")


def test_config_cannot_weaken_thresholds(monkeypatch, tmp_path):
    from depbouncer import config
    d = tmp_path / "dbhome"
    d.mkdir(exist_ok=True)
    (d / "config.toml").write_text("[thresholds]\nmin_age_days = 1\nmin_downloads_npm = 0\n", encoding="utf-8")
    c = config.load()
    assert c.min_age_days == 90 and c.min_downloads["npm"] == 1000
