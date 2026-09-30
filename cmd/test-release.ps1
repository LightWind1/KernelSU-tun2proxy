param([Parameter(Mandatory=$true)][string]$Package)
$ErrorActionPreference="Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Package))
try {
    $required=@('module.prop','service.sh','customize.sh','uninstall.sh','certificate/service.sh','system/bin/tun2proxy','system/bin/tun2proxy-web','system/bin/tun2proxy-tun-launcher','system/bin/ebpf-proxy','system/bpf/redirect.bpf.o','webroot/index.html','webroot/backend.js','LICENSES/ebpf-proxy/LICENSE','LICENSES/ebpf-proxy/THIRD_PARTY_NOTICES')
    foreach($path in $required){$entry=$archive.GetEntry($path);if(!$entry -or $entry.Length -eq 0){throw "Missing or empty runtime entry: $path"}}
    foreach($entry in $archive.Entries){if($entry.FullName -match '^(ebpf-proxy|cmd|\.git)/'){throw "Source/test directory leaked: $($entry.FullName)"}}
    foreach($path in @('system/bin/ebpf-proxy','system/bin/tun2proxy-web','system/bin/tun2proxy','system/bpf/redirect.bpf.o')){
        $stream=$archive.GetEntry($path).Open();$header=New-Object byte[] 20
        try{$n=0;while($n -lt 20){$read=$stream.Read($header,$n,20-$n);if($read -eq 0){throw "Truncated ELF: $path"};$n+=$read}}finally{$stream.Dispose()}
        if($header[0] -ne 127 -or $header[1] -ne 69 -or $header[2] -ne 76 -or $header[3] -ne 70){throw "Not ELF: $path"}
        $machine=[BitConverter]::ToUInt16($header,18);$expected=183;if($path.EndsWith('.bpf.o')){$expected=247};if($machine -ne $expected){throw "Wrong ELF machine for ${path}: $machine"}
    }
    $reader=New-Object System.IO.StreamReader($archive.GetEntry('module.prop').Open());try{$prop=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $source=Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'module.prop')
    $expectedVersion=[regex]::Match($source,'(?m)^version=([^\r\n]+)').Groups[1].Value
    $expectedCode=[regex]::Match($source,'(?m)^versionCode=(\d+)').Groups[1].Value
    if($prop -notmatch ('(?m)^version='+[regex]::Escape($expectedVersion)+'\r?$') -or $prop -notmatch ('(?m)^versionCode='+$expectedCode+'\r?$')){throw 'Release metadata mismatch'}
    Write-Output "Release ZIP verified: runtime entries, source exclusions, Android arm64/BPF ELF and version metadata"
} finally {$archive.Dispose()}
