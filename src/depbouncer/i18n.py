"""Turkish and English texts. A reason is a (code, params) pair."""

VERDICT = {
    "PASS": ("GEÇTİ", "PASSED"),
    "ASK": ("ONAY GEREKİYOR", "APPROVAL REQUIRED"),
    "BLOCK": ("ENGELLENDİ", "BLOCKED"),
}

TEXT = {
    # registry checks (ported from package-guard's check_package.py)
    "not_found": ("kayıtta böyle bir paket yok (uydurulmuş olabilir)",
                  "does not exist in the registry (possibly hallucinated)"),
    "version_not_found": ("bu sürüm bulunamadı", "version not found"),
    "security_placeholder": ("npm güvenlik yer tutucu paketi (zararlı paket kaldırılmış)",
                             "npm security placeholder package (malware was removed)"),
    "install_script": ("kurulum sırasında kod çalıştırıyor (install script)",
                       "runs code during install (install script)"),
    "deprecated": ("kullanımdan kaldırılmış (deprecated)", "deprecated"),
    "yanked": ("bu sürüm geri çekilmiş (yanked)", "version was yanked"),
    "sdist_only": ("yalnızca kaynak paketi var: kurulumda kod çalıştırır",
                   "source only: runs code during install"),
    "nuget_unlisted": ("NuGet aramasında listelenmiyor", "not listed in NuGet search"),
    "nuget_unverified": ("paket kimliği öneki doğrulanmamış", "package ID prefix not verified"),
    "http_error": ("doğrulanamadı: HTTP {code}", "could not verify: HTTP {code}"),
    "verify_error": ("doğrulanamadı: {err}", "could not verify: {err}"),
    "known_malware": ("bilinen zararlı yazılım: {ids}", "known malware: {ids}"),
    "malware_other_versions": ("başka sürümleri zararlı olarak bildirilmiş: {ids}",
                               "other versions were reported as malware: {ids}"),
    "advisories": ("bu sürüm için {n} bilinen güvenlik bildirimi var",
                   "{n} known security advisories for this version"),
    "osv_unreachable": ("zararlı yazılım veritabanına (OSV) ulaşılamadı: {err}",
                        "malware database (OSV) not reachable: {err}"),
    "new_package": ("çok yeni paket (< {days} gün)", "very new package (< {days} days)"),
    "date_unknown": ("yayın tarihi bilinmiyor", "publish date unknown"),
    "few_downloads": ("az indirilmiş ({n})", "few downloads ({n})"),
    "downloads_unavailable": ("indirme sayısı alınamadı ({err})", "download count unavailable ({err})"),
    "no_repo": ("depo veya proje bağlantısı yok", "no repository or project link"),
    # added checks
    "typosquat": ("popüler '{target}' paketine çok benzeyen ad (yazım hilesi olabilir)",
                  "name is very close to popular package '{target}' (possible typosquat)"),
    "non_registry": ("kayıt dışı kaynak (git, URL, yerel yol veya özel indeks): elle inceleyin: {spec}",
                     "not a registry package (git, URL, local path or custom index): review by hand: {spec}"),
    "bad_name": ("düz bir paket adı/sürümü değil: elle inceleyin", "not a plain package name/version: review by hand"),
    "range_unresolved": ("sürüm aralığı çözülemedi: {spec}", "could not resolve version range: {spec}"),
    "custom_registry": ("özel kayıt/indeks kullanılıyor ({flag}): denetlenemez",
                        "custom registry/index in use ({flag}): cannot be checked"),
    "private_pkg": ("özel paket listenizde: dışarıya sorulmadı", "on your private list: not sent anywhere"),
    "transitive_malware": ("alt bağımlılıkta bilinen zararlı yazılım: {items}",
                           "known malware in a sub-dependency: {items}"),
    "transitive_failed": ("alt bağımlılıklar denetlenemedi: {err}", "sub-dependencies could not be checked: {err}"),
    "unparsed_install": ("kurulum komutu ayrıştırılamadı, elle inceleyin", "install command could not be parsed, review by hand"),
    "tamper": ("koruma ayarlarına/onaylarına dokunma girişimi: {what}",
               "attempt to change the guard's settings or approvals: {what}"),
    "edit_unreadable": ("bağımlılık dosyası düzenlemesi değerlendirilemedi: {path}",
                        "could not evaluate the edit to a dependency file: {path}"),
    "too_many": ("denetlenecek paket sayısı çok fazla ({n})", "too many packages to check ({n})"),
    "internal_error": ("koruma hatası, güvenli tarafta kalındı: {err}", "guard error, failing safe: {err}"),
    "timeout": ("denetim zaman aşımına uğradı, güvenli tarafta kalındı", "check timed out, failing safe"),
    "undecidable_input": ("ajan isteği anlaşılamadı, güvenli tarafta kalındı", "could not understand the agent request, failing safe"),
    # facts (shown after reasons)
    "fact_version": ("sürüm {v}", "version {v}"),
    "fact_age": ("ilk yayın {days} gün önce", "first published {days} days ago"),
    "fact_downloads": ("indirme {n}", "downloads {n}"),
    "fact_transitive": ("{n} alt bağımlılık denetlendi", "{n} sub-dependencies checked"),
    "fact_transitive_adv": ("alt bağımlılıklarda {n} güvenlik bildirimi (zararlı değil)",
                            "{n} advisories in sub-dependencies (not malware)"),
    "fact_transitive_skipped": ("alt bağımlılık denetimi atlandı: {why}", "sub-dependency check skipped: {why}"),
    "fact_approved": ("kullanıcı onayı kullanıldı", "user approval used"),
    "fact_cached": ("önbellekten", "from cache"),
}

HOW_TO_APPROVE = (
    "Onay için KENDİ terminalinizde çalıştırın: depbouncer approve",
    "To approve, run in YOUR OWN terminal: depbouncer approve",
)
AGENT_NOTE = (
    "Ajan: bu komutu kendin çalıştırma, onayı kullanıcıdan iste; onaydan sonra aynı işlemi tekrar dene.",
    "Agent: do not run the approve command yourself; ask the user, then retry the same action after approval.",
)


def text(code, params, lang):
    tr, en = TEXT.get(code, (code, code))
    try:
        tr, en = tr.format(**params), en.format(**params)
    except (KeyError, IndexError):
        pass
    if lang == "tr":
        return tr
    if lang == "en":
        return en
    return tr if tr == en else f"{tr} / {en}"


def pick(pair, lang):
    tr, en = pair
    return tr if lang == "tr" else en if lang == "en" else f"{tr} / {en}"
