[CmdletBinding()]
param(
    [string]$P4Port,
    [string]$C6Port,
    [switch]$FlashP4,
    [switch]$FlashC6,
    [switch]$MonitorP4,
    [switch]$MonitorC6,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

if (($FlashP4 -or $MonitorP4) -and [string]::IsNullOrWhiteSpace($P4Port)) {
    throw "-P4Port is required when flashing or monitoring the ESP32-P4."
}
if (($FlashC6 -or $MonitorC6) -and [string]::IsNullOrWhiteSpace($C6Port)) {
    throw "-C6Port is required when flashing or monitoring the ESP32-C6."
}
if (-not [string]::IsNullOrWhiteSpace($P4Port) -and
    -not [string]::IsNullOrWhiteSpace($C6Port) -and
    $P4Port.Trim().ToLowerInvariant() -eq $C6Port.Trim().ToLowerInvariant()) {
    throw "P4 and C6 ports must be selected explicitly and must be different."
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot
try {
    if (-not $NoBuild -or $FlashC6 -or $MonitorC6) {
        $c6Args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                    "$PSScriptRoot/build_c6_coprocessor.ps1")
        if ($FlashC6 -or $MonitorC6) { $c6Args += @("-Port", $C6Port) }
        if ($FlashC6) { $c6Args += "-Upload" }
        if ($MonitorC6) { $c6Args += "-Monitor" }
        & powershell @c6Args
        if ($LASTEXITCODE -ne 0) { throw "ESP32-C6 workflow failed." }
    }

    $p4Args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                "$PSScriptRoot/build_flash.ps1", "-Target",
                "guition-jc-esp32p4-m3-dev")
    if ($FlashP4 -or $MonitorP4) { $p4Args += @("-Port", $P4Port) }
    if ($FlashP4) { $p4Args += "-Upload" }
    if ($MonitorP4) { $p4Args += "-Monitor" }
    if ($NoBuild) { $p4Args += "-NoBuild" }
    & powershell @p4Args
    if ($LASTEXITCODE -ne 0) { throw "ESP32-P4 workflow failed." }
} finally {
    Pop-Location
}
