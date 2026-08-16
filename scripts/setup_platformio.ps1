[CmdletBinding()]
param(
    [switch]$InstallVsCodeExtension
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $ProjectRoot ".venv"
$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $Python) { throw "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/ and retry." }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "Git is required and was not found on PATH." }

Push-Location $ProjectRoot
try {
    if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
        & $Python.Source -m venv $Venv
    }
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install --upgrade platformio esptool
    & git submodule update --init --recursive
    if ($InstallVsCodeExtension) {
        $Code = Get-Command code -ErrorAction SilentlyContinue
        if (-not $Code) { throw "VS Code CLI 'code' was not found. Install VS Code or omit -InstallVsCodeExtension." }
        & $Code.Source --install-extension platformio.platformio-ide
    }
    Write-Host "Setup complete. Use $VenvPython -m platformio for builds."
    Write-Host "In VS Code, open this folder and select the interpreter $VenvPython."
} finally {
    Pop-Location
}
