[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("t-poe-pro", "esp32-s3-eth", "waveshare-esp32p4-eth")]
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
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }
Push-Location $ProjectRoot
try {
    if (-not $NoBuild) { & $Python -m platformio run -e $Target }
    if ($Upload) { & $Python scripts/flash_esptool.py --target $Target --port $Port --no-build }
    if ($Monitor) { & $Python -m platformio device monitor --port $Port --baud $Baud }
} finally {
    Pop-Location
}
