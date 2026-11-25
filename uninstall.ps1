<#
.SYNOPSIS
  Removes only what depbouncer added (hooks carrying the depbouncer marker,
  the /pc-scan skill, the PATH entry, the app copy). Agent files are backed up
  first; backups are kept in %LOCALAPPDATA%\depbouncer\backups.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge   # also settings, cache, scan data
#>
param([switch]$DryRun, [switch]$Purge)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'depbouncer'
$cmd = Join-Path $root 'bin\depbouncer.cmd'
$app = Join-Path $root 'app\launcher.py'
$a = @('uninstall')
if ($DryRun) { $a += '--dry-run' }
if ($Purge) { $a += '--purge' }
if (Test-Path $cmd) {
  $line = (Get-Content $cmd | Select-String -Pattern '^"(.+?)"' | Select-Object -First 1)
  $python = if ($line) { $line.Matches[0].Groups[1].Value } else { $null }
}
if (-not $python -or -not (Test-Path $python)) {
  $python = (& py -3 -c "import sys;print(sys.executable)").Trim()
}
$src = if (Test-Path $app) { $app } else { Join-Path $PSScriptRoot 'src\launcher.py' }
& $python -I $src @a
if (-not $DryRun) {
  Remove-Item -Recurse -Force (Join-Path $root 'app') -ErrorAction SilentlyContinue
}
