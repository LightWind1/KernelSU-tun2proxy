param([string]$Go="go",[string]$Ndk="$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358")
$ErrorActionPreference="Stop"
& "$PSScriptRoot\ebpf-proxy\build.ps1" -Go $Go -Ndk $Ndk
New-Item -ItemType Directory -Force "$PSScriptRoot\system\bpf" | Out-Null
Copy-Item -LiteralPath "$PSScriptRoot\ebpf-proxy\build\ebpf-proxy-android" -Destination "$PSScriptRoot\system\bin\ebpf-proxy"
Copy-Item -LiteralPath "$PSScriptRoot\ebpf-proxy\build\redirect.bpf.o" -Destination "$PSScriptRoot\system\bpf\redirect.bpf.o"
New-Item -ItemType Directory -Force "$PSScriptRoot\licenses\ebpf-proxy" | Out-Null
Copy-Item -LiteralPath "$PSScriptRoot\ebpf-proxy\LICENSE", "$PSScriptRoot\ebpf-proxy\THIRD_PARTY_NOTICES" -Destination "$PSScriptRoot\licenses\ebpf-proxy"
