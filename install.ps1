<#
.SYNOPSIS
  depbouncer installer (Windows). Registers global hooks for Claude Code, Codex,
  Cursor and Antigravity, plus a /pc-scan skill. Backs up every agent file first.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -DryRun
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Agents claude,cursor
#>
param(
  [string[]]$Agents = @(),
  [switch]$DryRun,
  [switch]$NoPath
)
$ErrorActionPreference = 'Stop'

function Find-RealPython {
  # The Microsoft Store "python" alias (WindowsApps) is not a real Python: hooks
  # pointing at it would fail on every call. Use the py launcher or a full path.
  $candidates = @()
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    foreach ($v in @('-3.13', '-3.12', '-3.11', '-3')) {
      try {
        $exe = & $py.Source $v -c "import sys;print(sys.executable if sys.version_info>=(3,11) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { $candidates += $exe.Trim() }
      } catch {}
    }
  }
  foreach ($name in @('python', 'python3')) {
    $c = Get-Command $name -ErrorAction SilentlyContinue
    if ($c -and $c.Source -notmatch 'WindowsApps') {
      try {
        $exe = & $c.Source -c "import sys;print(sys.executable if sys.version_info>=(3,11) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { $candidates += $exe.Trim() }
      } catch {}
    }
  }
  foreach ($c in $candidates) {
    if ($c -and (Test-Path $c) -and ($c -notmatch 'WindowsApps')) { return $c }
  }
  return $null
}

$python = Find-RealPython
if (-not $python) {
  Write-Host "Python 3.11+ bulunamadi / not found. https://www.python.org/downloads/ (Store surumu degil / not the Store alias)" -ForegroundColor Red
  exit 1
}
$launcher = Join-Path $PSScriptRoot 'src\launcher.py'
$args2 = @('-I', $launcher, 'install')
if ($Agents.Count -gt 0) { $args2 += '--agents'; $args2 += $Agents }
if ($DryRun) { $args2 += '--dry-run' }
if ($NoPath) { $args2 += '--no-path' }
& $python @args2
$code = $LASTEXITCODE
if ($code -eq 0 -and -not $DryRun) {
  $bin = Join-Path $env:LOCALAPPDATA 'depbouncer\bin\depbouncer.cmd'
  & $bin doctor
}
exit $code
