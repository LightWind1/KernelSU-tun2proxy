param([string]$Sdk = "$env:LOCALAPPDATA\Android\Sdk", [string]$JavaHome = "C:\Program Files\Android\Android Studio\jbr")
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$classes = Join-Path $PSScriptRoot "certificate-probe\build"
New-Item -ItemType Directory -Force $classes | Out-Null
$framework = Join-Path $repo "system\framework"
New-Item -ItemType Directory -Force $framework | Out-Null
& "$JavaHome\bin\javac.exe" --release 8 -d $classes "$PSScriptRoot\certificate-probe\CertificateProbe.java"
if ($LASTEXITCODE -ne 0) { throw "CertificateProbe javac failed" }
$env:JAVA_HOME = $JavaHome
& "$Sdk\build-tools\36.0.0\d8.bat" --min-api 24 --output "$framework\certificate-probe.jar" "$classes\CertificateProbe.class"
if ($LASTEXITCODE -ne 0) { throw "CertificateProbe DEX build failed" }
Write-Output "Built public-certificate AndroidCAStore probe"
