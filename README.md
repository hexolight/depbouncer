# depbouncer

**[Türkçe](README.tr.md)** · English

A gatekeeper for packages that AI coding agents add. Before Claude Code, Codex,
Cursor or Antigravity installs an npm, PyPI or NuGet package (or edits a
dependency file), depbouncer checks it and answers **PASSED**, **APPROVAL
REQUIRED** or **BLOCKED**, with the reasons in Turkish and English.

MIT licensed · Windows first · Python 3.11+ standard library only (no dependencies).

## Install (Windows, one command)

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

- Finds a real Python 3.11+ with the `py` launcher. The Microsoft Store `python`
  alias is refused, because hooks pointing at it would fail on every call.
- Copies the app to `%LOCALAPPDATA%\depbouncer\app` and adds `depbouncer` to your user PATH.
- Registers **global** hooks for the agents it finds, and a `/pc-scan` skill.
- **Backs up** every agent file to `%LOCALAPPDATA%\depbouncer\backups\<time>\` before touching it.
  It merges with your existing settings and hooks and never overwrites them. A file it cannot parse is left alone.
- Runs `depbouncer doctor` at the end, which includes the OSV self-test.

Options: `-DryRun` (show what would change), `-Agents claude,cursor`, `-NoPath`.

**Codex only:** open `/hooks` in Codex once and *trust* the depbouncer hook. Codex does not run untrusted user hooks.
**Cursor / Antigravity:** restart the app so it reloads hooks.

Uninstall (removes only entries carrying the depbouncer marker, keeps backups):

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

## What is checked

The check runs before an agent does any of the following:

| Trigger | Covered |
|---|---|
| Commands | `npm/pnpm/yarn/bun install·add·ci·update`, `npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `npm create/init`, `pip/pip3/python -m pip/py -m pip install`, `uv add`, `uv pip install`, `uv sync`, `uvx`, `uv tool install`, `uv run --with`, `pipx`, `dotnet add package`, `dotnet package add`, `dotnet tool install`, `dotnet restore`, `nuget install`, `Install-Package` — also inside `cmd /c`, `powershell -Command`, `-EncodedCommand`, `bash -c`, chained with `&&`, `;` or `|` |
| File edits | `package.json`, `requirements*.txt`, `pyproject.toml` (PEP 621, Poetry, uv, dependency groups), `Pipfile`, `*.csproj/fsproj/vbproj`, `Directory.Packages.props`, `packages.config`. Only **added or changed** dependencies are checked |

For each package (npm, PyPI, NuGet), the engine of the original `package-guard` script is kept, with every check and threshold:

- exists in the registry (missing = **BLOCKED**: a typical hallucinated name)
- OSV malware record for this version (**BLOCKED**), or for other versions (**APPROVAL REQUIRED**)
- other OSV advisories, age < 90 days, few downloads, install scripts or source-only builds, deprecated or yanked versions, no repository link, NuGet prefix not verified
- added in this version:
  - look-alike names, compared with bundled lists of the ~3000 most popular names per ecosystem
  - version ranges resolved the way each package manager resolves them
  - sub-dependencies:
    - npm: lockfile generated with `--package-lock-only --ignore-scripts`; nothing is installed and no install code runs
    - PyPI: `pip --dry-run --only-binary=:all:`, wheels only, so nothing is built
    - NuGet: dependency graph read from the registry
    - all of them are checked against OSV in one batch

Run a check by hand: `depbouncer check npm express@4.21.2` (exit 0 PASS, 1 ASK, 2 BLOCK).

## Safety rules

- **Fail closed.** A crash, timeout (90 s inside the hook), unreadable input or uncertain result never lets an install through.
  If Python itself cannot start, the launcher still blocks:
  - exit 2 for Claude Code and Cursor;
  - a JSON "deny" for Codex and Antigravity.

  The agent's own safety switch is turned on as well: `onFailure: "block"` in Claude Code, `failClosed: true` in Cursor.
- **The agent cannot approve itself.** Where an agent's "ask" really prompts the user, it is used:
  - Claude Code, only in default, plan and acceptEdits modes;
  - Cursor shell commands;
  - Antigravity (`force_ask`).

  Everywhere else "ask" becomes "deny" with an approval path.
  The user runs `depbouncer approve` in their **own** terminal; it opens a native Windows dialog. Each approval:
  - covers one exact package@version,
  - can be used once,
  - expires after 30 minutes.

  Agent commands containing `depbouncer approve`, and writes to depbouncer's data or to the agents' hook settings files, are blocked.
  A BLOCKED result cannot be approved.
- **Privacy.**
  - Only package names and versions leave the machine, and only to a fixed list of public hosts (npm, PyPI, NuGet, pypistats, OSV).
  - Private packages are listed in `%LOCALAPPDATA%\depbouncer\config.toml` → `[private]`. They are never sent anywhere and are answered APPROVAL REQUIRED, or PASSED if you set `result = "pass"`.
  - Commands that use a custom registry or index are APPROVAL REQUIRED and send nothing.
- **Settings can only make checks stricter.** For example, `min_age_days` below 90 is ignored.

## /pc-scan

Type `/pc-scan` in Claude Code, Codex (`$pc-scan` or `/skills`), Cursor or Antigravity. You can also run `depbouncer scan` yourself, and `depbouncer scan --status` shows progress.

- Read-only, low priority (Windows background mode), one folder at a time. Progress is saved every few seconds and the scan resumes where it stopped.
- Starts with an OSV self-test: `flatmap-stream@0.1.1` (the 2018 event-stream incident) must come back as malware, otherwise the scan stops. Only the name is queried; nothing is downloaded.
- Reads only lockfiles and installed-package metadata:
  - npm lock files, `node_modules`, pnpm store
  - `*.dist-info`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt`
  - `%USERPROFILE%\.nuget\packages`, `packages.lock.json`, `project.assets.json`
- **Never opens** browser profiles, Windows credential stores, `.ssh`, `.aws` and similar folders, `.env` files, keys or cookies. Windows Defender is not used.
- Report: `%LOCALAPPDATA%\depbouncer\scan\report.md`. Each finding shows its evidence (OSV id and link, package, version, file path) and a false-alarm rating:
  - **high**: installed, exact version match
  - **medium**: in a lockfile only
  - **low**: name only, version unknown

  The report also lists everything that was **not** scanned.

## Limits (read this)

- PASSED never means safe. It means no warning sign was found. New malware without an OSV record is not detected.
- The agent runs as your Windows user. The approval files are protected by hooks and by the dialog, not by the operating system. An agent that gets around the hooks could still change them.
- Hooks only see the agent's tools. Packages installed some other way are not intercepted, for example by a script the agent writes and runs later, an MCP server, or a terminal you type in.
- The download-count service (pypistats) rate-limits. When it does, the result is APPROVAL REQUIRED, not PASSED.
- Cursor's `preToolUse` input format for file edits is not documented. Edits whose result cannot be reconstructed are APPROVAL REQUIRED, and Cursor then denies them.
- Version ranges: common npm, PEP 440 and NuGet range forms are supported. Anything else is APPROVAL REQUIRED.
- Sub-dependency checks need `npm` (for npm) and `pip` (for PyPI). If they fail, the result is APPROVAL REQUIRED.
- The tamper rule is strict on purpose: a command that names a hook settings file or the depbouncer folder and uses a tool that could write (`python`, `node`, `echo`, `>` …) is blocked even if it only reads. Let the agent use its own file-read tool for those files.

## Tested for real / not tested (2026-11-25, Windows 11)

| Agent | Version | Tried for real | Result | Not tried |
|---|---|---|---|---|
| Codex | codex-cli 0.167.0-alpha | ✅ `codex exec` with the hook supplied through `-c` | npm install of a missing package → **Blocked**, reason reached the model. Package with an install script → deny + `depbouncer approve` path, model did not self-approve. Python missing → **Blocked**. `apply_patch` on package.json → **Blocked** | the `/hooks` trust UI, the `$pc-scan` skill |
| Claude Code | 2.1.330 (desktop) | ✅ live session with the global hook after the real install (2026-11-26, auto mode) | `echo` → passed. npm install of a missing package → **blocked**. `esbuild` (install script + advisory) → in auto mode "ask" became deny + `depbouncer approve` path. A Python command naming the hook settings file → **blocked** by the tamper rule | the native "ask" prompt in default/plan mode, the `/pc-scan` skill |
| Cursor | installed (IDE) | ❌ (no headless CLI) | hook command run through PowerShell with piped JSON: block, allow, BOM handling | live IDE session, the `/pc-scan` skill |
| Antigravity | agy 1.2.14 | ⚠️ `agy -p` started, but in headless mode it auto-denied the command before the hook ran | hook command run through cmd and PowerShell: deny, allow, garbage input | live hook in the app or CLI, the `/pc-scan` skill |

The unit tests (166) run on Windows CI with Python 3.11–3.13 plus Ubuntu. All registry and OSV answers in the tests are fakes, and no real malicious package is ever downloaded or installed.

## Development

```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\python -m pip install pytest==9.2.0
.\.venv\Scripts\python -m pytest -q
```
