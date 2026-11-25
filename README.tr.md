# depbouncer

Türkçe · **[English](README.md)**

Yapay zekâ kodlama ajanlarının eklediği paketler için bir kapı görevlisi.
Claude Code, Codex, Cursor veya Antigravity bir npm, PyPI ya da NuGet paketi
kurmadan (veya bağımlılık dosyasını değiştirmeden) önce depbouncer paketi
denetler. Sonuç **GEÇTİ**, **ONAY GEREKİYOR** veya **ENGELLENDİ** olur;
gerekçe Türkçe ve İngilizce verilir.

MIT lisanslı · Windows öncelikli · yalnızca Python 3.11+ standart kütüphanesi (ek bağımlılık yok).

## Kurulum (Windows, tek komut)

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

- Gerçek Python 3.11+ sürümünü `py` başlatıcısıyla bulur. Microsoft Store'un `python` kısayolunu kabul etmez; o kısayola bağlanan hook her çağrıda hata verirdi.
- Uygulamayı `%LOCALAPPDATA%\depbouncer\app` klasörüne kopyalar ve `depbouncer` komutunu kullanıcı PATH'ine ekler.
- Bulduğu ajanlara **global** hook'ları ve `/pc-scan` skill'ini kaydeder.
- Her ajan dosyasını değiştirmeden önce `%LOCALAPPDATA%\depbouncer\backups\<zaman>\` altına **yedekler**.
  Mevcut ayar ve hook'larınızı korur, üzerine yazmaz. Okuyamadığı bir dosyaya hiç dokunmaz.
- Sonunda `depbouncer doctor` çalışır; buna OSV öz-sınaması da dahildir.

Seçenekler: `-DryRun` (yalnızca ne değişeceğini gösterir), `-Agents claude,cursor`, `-NoPath`.

**Yalnızca Codex:** Codex'te bir kez `/hooks` açıp depbouncer hook'una *güvenin* (trust). Codex güvenilmemiş kullanıcı hook'larını çalıştırmaz.
**Cursor / Antigravity:** hook'ları yeniden yüklemesi için uygulamayı yeniden başlatın.

Kaldırma (yalnızca depbouncer işaretli kayıtları siler, yedekleri tutar):

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

## Neler denetleniyor

Denetim, ajan aşağıdakilerden birini yapmadan önce çalışır:

| Tetikleyici | Kapsam |
|---|---|
| Komutlar | `npm/pnpm/yarn/bun install·add·ci·update`, `npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `npm create/init`, `pip/pip3/python -m pip/py -m pip install`, `uv add`, `uv pip install`, `uv sync`, `uvx`, `uv tool install`, `uv run --with`, `pipx`, `dotnet add package`, `dotnet package add`, `dotnet tool install`, `dotnet restore`, `nuget install`, `Install-Package`. `cmd /c`, `powershell -Command`, `-EncodedCommand`, `bash -c` içindekiler ve `&&`, `;`, `|` ile zincirlenenler de dahil |
| Dosya düzenlemeleri | `package.json`, `requirements*.txt`, `pyproject.toml` (PEP 621, Poetry, uv, bağımlılık grupları), `Pipfile`, `*.csproj/fsproj/vbproj`, `Directory.Packages.props`, `packages.config`. Yalnızca **eklenen veya değişen** bağımlılıklar denetlenir |

Her paket (npm, PyPI, NuGet) için `package-guard` skill'indeki script'in motoru tüm denetimleri ve eşikleriyle korunur:

- kayıtta var mı (yoksa **ENGELLENDİ**: tipik bir uydurulmuş ad)
- bu sürüm için OSV zararlı kaydı (**ENGELLENDİ**) veya başka sürümler için kayıt (**ONAY GEREKİYOR**)
- diğer OSV güvenlik bildirimleri, 90 günden yeni olması, az indirilmesi, kurulum script'i ya da yalnızca kaynak paketi olması, kullanımdan kaldırılmış veya geri çekilmiş sürüm, depo bağlantısının olmaması, NuGet önekinin doğrulanmamış olması
- bu sürümde eklenenler:
  - benzer ad (yazım hilesi) denetimi: her ekosistemin en popüler ~3000 adının pakete gömülü listeleriyle karşılaştırma
  - sürüm aralıklarının her paket yöneticisinin kendi kuralıyla çözülmesi
  - alt bağımlılıklar:
    - npm: `--package-lock-only --ignore-scripts` ile kilit dosyası üretilir; hiçbir şey kurulmaz ve kurulum kodu çalışmaz
    - PyPI: `pip --dry-run --only-binary=:all:`, yalnızca hazır paketler kullanılır, derleme yapılmaz
    - NuGet: bağımlılık ağacı kayıttan okunur
    - hepsi OSV'de tek seferde toplu sorgulanır

Elle denetim: `depbouncer check npm express@4.21.2` (çıkış kodu 0 GEÇTİ, 1 ONAY, 2 ENGEL).

## Güvenlik kuralları

- **Hata olursa izin yok.** Çökme, zaman aşımı (hook içinde 90 sn), anlaşılmayan girdi veya belirsiz sonuç hiçbir zaman kuruluma izin vermez.
  Python hiç başlayamazsa da başlatıcı engeller:
  - Claude Code ve Cursor'da çıkış kodu 2 ile,
  - Codex ve Antigravity'de JSON "deny" ile.

  Ajanın kendi emniyet ayarı da açılır: Claude Code'da `onFailure: "block"`, Cursor'da `failClosed: true`.
- **Ajan kendine onay veremez.** Ajanın "ask" özelliği gerçekten kullanıcıya soruyorsa kullanılır:
  - Claude Code'da yalnızca default, plan ve acceptEdits modlarında,
  - Cursor'da kabuk komutlarında,
  - Antigravity'de (`force_ask`).

  Diğer her yerde "ask" yerine "deny" verilir ve onay yolu gösterilir.
  Kullanıcı **kendi** terminalinde `depbouncer approve` çalıştırır; bu komut bir Windows onay penceresi açar. Her onay:
  - tek bir paket@sürüm içindir,
  - bir kez kullanılabilir,
  - 30 dakika sonra geçersiz olur.

  Ajanın `depbouncer approve` içeren komutları, depbouncer verisine ya da ajanların hook ayar dosyalarına yazma girişimleri engellenir.
  ENGELLENDİ sonucu onayla aşılamaz.
- **Gizlilik.**
  - Dışarıya yalnızca paket adı ve sürümü, sabit bir genel sunucu listesine gider (npm, PyPI, NuGet, pypistats, OSV).
  - Özel paketler `%LOCALAPPDATA%\depbouncer\config.toml` → `[private]` altına yazılır. Bunlar hiçbir yere gönderilmez ve ONAY GEREKİYOR olarak yanıtlanır; `result = "pass"` derseniz GEÇTİ olur.
  - Özel kayıt/indeks kullanan komutlar ONAY GEREKİYOR olur ve dışarıya hiçbir şey göndermez.
- **Ayarlar denetimi yalnızca sıkılaştırabilir.** Örneğin `min_age_days` için 90'dan küçük bir değer yok sayılır.

## /pc-scan

Claude Code, Codex (`$pc-scan` veya `/skills`), Cursor veya Antigravity'de `/pc-scan` yazın. Taramayı kendiniz `depbouncer scan` ile de başlatabilirsiniz; ilerlemeyi `depbouncer scan --status` gösterir.

- Salt okunur, düşük öncelikli (Windows arka plan modu) ve her seferinde tek klasör işler. İlerleme birkaç saniyede bir kaydedilir; tarama durursa kaldığı yerden sürer.
- Başta OSV öz-sınaması yapılır: `flatmap-stream@0.1.1` (2018'deki event-stream olayı) zararlı olarak dönmezse tarama durur. Yalnızca ad sorgulanır, hiçbir şey indirilmez.
- Yalnızca kilit dosyalarını ve kurulu paket bilgilerini okur:
  - npm kilit dosyaları, `node_modules`, pnpm deposu
  - `*.dist-info`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt`
  - `%USERPROFILE%\.nuget\packages`, `packages.lock.json`, `project.assets.json`
- Tarayıcı profillerini, Windows kimlik depolarını, `.ssh`, `.aws` gibi klasörleri, `.env` dosyalarını, anahtarları ve çerezleri **hiç açmaz**. Windows Defender kullanılmaz.
- Rapor: `%LOCALAPPDATA%\depbouncer\scan\report.md`. Her bulgu kanıtıyla gösterilir (OSV kimliği ve bağlantısı, paket, sürüm, dosya yolu) ve yanlış alarm olasılığı derecelendirilir:
  - **yüksek güven**: kurulu ve sürüm tam eşleşiyor
  - **orta**: yalnızca kilit dosyasında
  - **düşük**: yalnızca ad var, sürüm bilinmiyor

  Raporda **taranmayan** her şey de listelenir.

## Sınırlar (lütfen okuyun)

- GEÇTİ hiçbir zaman "güvenli" demek değildir; yalnızca uyarı işareti bulunmadığı anlamına gelir. OSV'de kaydı olmayan yeni zararlılar yakalanmaz.
- Ajan sizin Windows kullanıcınızla çalışır. Onay dosyaları işletim sistemiyle değil, hook'lar ve onay penceresiyle korunur. Hook'ları atlatan bir ajan yine de bu dosyaları değiştirebilir.
- Hook'lar yalnızca ajanın araçlarını görür. Başka yollarla kurulan paketler yakalanmaz; örneğin ajanın yazıp daha sonra çalıştırdığı bir script, bir MCP sunucusu ya da sizin elle komut yazdığınız bir terminal.
- İndirme sayısı servisi (pypistats) istek sınırı uygulayabilir. Bu olduğunda sonuç GEÇTİ değil ONAY GEREKİYOR olur.
- Cursor'un `preToolUse` girdisindeki dosya düzenleme biçimi belgelenmemiştir. Sonucu yeniden kurulamayan düzenlemeler ONAY GEREKİYOR olur ve Cursor bunları reddeder.
- Sürüm aralıkları: yaygın npm, PEP 440 ve NuGet aralık biçimleri desteklenir. Bunların dışındakiler ONAY GEREKİYOR olur.
- Alt bağımlılık denetimi npm için `npm`, PyPI için `pip` gerektirir. Bu adım başarısız olursa sonuç ONAY GEREKİYOR olur.
- Koruma kuralı bilerek katıdır: hook ayar dosyalarının veya depbouncer klasörünün yolunu içeren ve yazabilecek bir araç (`python`, `node`, `echo`, `>` …) kullanan komutlar, salt okunur olsalar bile engellenir. Bu dosyaları ajana okutmak için ajanın kendi dosya okuma aracını kullanın.

## Gerçekte denendi / denenmedi (2026-11-25, Windows 11)

| Ajan | Sürüm | Gerçekte denendi | Sonuç | Denenmedi |
|---|---|---|---|---|
| Codex | codex-cli 0.167.0-alpha | ✅ `codex exec`, hook `-c` ile verildi | Var olmayan paketin npm kurulumu → **Blocked**, gerekçe modele ulaştı. Kurulum script'li paket → red + `depbouncer approve` yolu, model kendine onay vermedi. Python yok → **Blocked**. package.json'a `apply_patch` → **Blocked** | `/hooks` güven ekranı, `$pc-scan` skill'i |
| Claude Code | 2.1.330 (masaüstü) | ✅ Gerçek kurulumdan sonra global hook'lu canlı oturum (2026-11-26, auto modu) | `echo` → geçti. Var olmayan paketin npm kurulumu → **engellendi**. `esbuild` (install script + bildirim) → auto modda "ask" yerine red + `depbouncer approve` yolu. Hook ayar dosyasının yolunu içeren bir Python komutu → koruma kuralıyla **engellendi** | default/plan modunda yerel "ask" penceresi, `/pc-scan` skill'i |
| Cursor | kurulu (IDE) | ❌ (headless CLI yok) | Hook komutu PowerShell'den, boru ile JSON verilerek çalıştırıldı: engel, izin, BOM işleme | Canlı IDE oturumu, `/pc-scan` skill'i |
| Antigravity | agy 1.2.14 | ⚠️ `agy -p` başladı, ancak headless modda komutu hook çalışmadan önce kendisi reddetti | Hook komutu cmd ve PowerShell'den çalıştırıldı: red, izin, bozuk girdi | Uygulamada veya CLI'da canlı hook, `/pc-scan` skill'i |

Birim testleri (166) Windows CI'da Python 3.11–3.13 ile ve ayrıca Ubuntu'da çalışır. Testlerdeki tüm kayıt ve OSV yanıtları sahtedir; hiçbir gerçek zararlı paket indirilmez veya kurulmaz.

## Geliştirme

```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\python -m pip install pytest==9.2.0
.\.venv\Scripts\python -m pytest -q
```
