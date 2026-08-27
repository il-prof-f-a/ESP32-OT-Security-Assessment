[CmdletBinding()]
param(
    [string]$Port,
    [switch]$Upload,
    [switch]$Monitor,
    [ValidateSet("PlatformIO", "EspIdf")]
    [string]$BuildSystem = "PlatformIO",
    [string]$BuildDir
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectDir = Join-Path $repoRoot "coprocessor\esp32c6"
$userProfileDir = [Environment]::GetFolderPath("UserProfile")
$platformioRoot = Join-Path $userProfileDir ".platformio"

if (-not $BuildDir) {
    $BuildDir = Join-Path $platformioRoot "build\ESP32-OT-Security-Assessment-coprocessor\esp32c6-coprocessor"
}

if ($BuildSystem -eq "PlatformIO") {
    $pio = Get-Command platformio -ErrorAction SilentlyContinue
    if (-not $pio) {
        $pioPath = Join-Path $platformioRoot "penv\Scripts\platformio.exe"
        if (-not (Test-Path -LiteralPath $pioPath)) {
            throw "PlatformIO was not found. Install PlatformIO Core or use -BuildSystem EspIdf."
        }
        $pioCommand = $pioPath
    } else {
        $pioCommand = $pio.Source
    }

    $arguments = @("run", "--project-dir", $projectDir, "-e", "esp32c6-coprocessor")
    if ($Upload) {
        if (-not $Port) { throw "-Port is required with -Upload." }
        $arguments += @("--target", "upload", "--upload-port", $Port)
    }
    & $pioCommand @arguments
    if ($LASTEXITCODE -ne 0) { throw "ESP32-C6 PlatformIO build failed." }

    if ($Monitor) {
        if (-not $Port) { throw "-Port is required with -Monitor." }
        & $pioCommand "device" "monitor" "--port" $Port "--baud" "115200"
        if ($LASTEXITCODE -ne 0) { throw "ESP32-C6 serial monitor failed." }
    }
} else {
    $framework = Get-ChildItem -LiteralPath (Join-Path $platformioRoot "packages") `
        -Directory -Filter "framework-espidf@*" | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $framework) { throw "A PlatformIO ESP-IDF 5.5 package was not found." }

    $pythonPath = Join-Path $platformioRoot "penv\.espidf-5.5.3\Scripts\python.exe"
    $idfPy = Join-Path $framework.FullName "tools\idf.py"
    if (-not (Test-Path -LiteralPath $pythonPath)) { throw "ESP-IDF Python environment was not found." }
    if (-not (Test-Path -LiteralPath $idfPy)) { throw "idf.py was not found in the ESP-IDF package." }

    $env:IDF_PATH = $framework.FullName
    $env:IDF_TARGET = "esp32c6"
    $arguments = @($idfPy, "-C", $projectDir, "-B", $BuildDir, "build")
    if ($Upload) {
        if (-not $Port) { throw "-Port is required with -Upload." }
        $arguments[-1] = "flash"
        $arguments += @("-p", $Port)
    }
    & $pythonPath @arguments
    if ($LASTEXITCODE -ne 0) { throw "ESP32-C6 idf.py build failed." }
}

Write-Host "ESP32-C6 artifacts: $BuildDir"
