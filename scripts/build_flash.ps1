[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("t-poe-pro", "esp32-s3-eth", "waveshare-esp32p4-eth", "guition-jc-esp32p4-m3-dev")]
    [string]$Target,
    [string]$Port,
    [switch]$Upload,
    [switch]$Monitor,
    [int]$Baud = 115200,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
if (($Upload -or $Monitor) -and [string]::IsNullOrWhiteSpace($Port)) {
    throw "-Port is required when using -Upload or -Monitor."
}
$ProjectRoot = Split-Path -Parent $PSScriptRoot

# Locate PlatformIO Core (standard install: ~/.platformio/penv), then fall back to PATH.
$Pio = Join-Path $env:USERPROFILE ".platformio\penv\Scripts\pio.exe"
if (-not (Test-Path $Pio)) {
    $pioCmd = Get-Command "pio" -ErrorAction SilentlyContinue
    if ($pioCmd) { $Pio = $pioCmd.Source } else { throw "PlatformIO (pio) not found. Install PlatformIO Core." }
}

# Locate a Python with esptool for flash_esptool.py (prefer the PlatformIO penv Python).
$Python = Join-Path $env:USERPROFILE ".platformio\penv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }

Push-Location $ProjectRoot
try {
    if (-not $NoBuild) {
        & $Pio run -e $Target; if ($LASTEXITCODE -ne 0) { throw "PlatformIO build failed" }
        & $Pio run -e $Target -t buildfs; if ($LASTEXITCODE -ne 0) { throw "PlatformIO filesystem build failed" }
    }
    if ($Upload) { & $Python scripts/flash_esptool.py --target $Target --port $Port --no-build; if ($LASTEXITCODE -ne 0) { throw "Flash failed" } }
    if ($Monitor) { & $Pio device monitor --port $Port --baud $Baud }
} finally {
    Pop-Location
}
