param([string]$Ndk="$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358", [string]$Go="go")
$ErrorActionPreference="Stop"
$root=$PSScriptRoot
New-Item -ItemType Directory -Force (Join-Path $root "build") | Out-Null
$llvm=Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64"
& "$llvm\bin\clang.exe" -target bpfel -O2 -g -I "$llvm\sysroot\usr\include" -I "$llvm\sysroot\usr\include\aarch64-linux-android" -c "$root\bpf\redirect.bpf.c" -o "$root\build\redirect.bpf.o"
if($LASTEXITCODE -ne 0){throw "BPF compile failed"}
$env:GOOS="linux";$env:GOARCH="arm64";$env:CGO_ENABLED="0"
& $Go -C $root build -trimpath -ldflags "-s -w" -o build/ebpf-proxy-android ./cmd/ebpf-proxy
if($LASTEXITCODE -ne 0){throw "Android daemon compile failed"}
