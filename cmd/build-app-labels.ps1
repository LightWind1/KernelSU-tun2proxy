param(
    [string]$Sdk = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$JavaHome = "C:\Program Files\Android\Android Studio\jbr"
)
$ErrorActionPreference = "Stop"
$classes = Join-Path $PSScriptRoot "app-labels\build"
$framework = Join-Path (Split-Path -Parent $PSScriptRoot) "system\framework"
New-Item -ItemType Directory -Force $classes, $framework | Out-Null
& "$JavaHome\bin\javac.exe" -source 8 -target 8 -cp "$Sdk\platforms\android-36\android.jar" -d $classes "$PSScriptRoot\app-labels\AppLabels.java"
if ($LASTEXITCODE -ne 0) { throw "AppLabels javac failed" }
$env:JAVA_HOME = $JavaHome
& "$Sdk\build-tools\36.0.0\d8.bat" --min-api 24 --output "$framework\app-labels.jar" "$classes\AppLabels.class"
if ($LASTEXITCODE -ne 0) { throw "AppLabels DEX build failed" }
Write-Output "Built Android application-label helper"
