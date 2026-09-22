$ErrorActionPreference = "Stop"

$moduleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$version = "v1.0.24"
$output = Join-Path (Split-Path -Parent $moduleDir) "tun2proxy-for-KernelSU-$version.zip"

# Files/directories to EXCLUDE from the module zip
$excludeDirs = @(
    ".git",
    ".claude",
    "cmd",
    "META-INF",
    "_pkg_stage"
)
$excludeFiles = @(
    "pack.sh",
    "pack.ps1",
    "build-tun2proxy.sh",
    "build-tun2proxy.ps1",
    "install.sh",
    "install.ps1",
    "go.mod",
    "go.sum",
    "CLAUDE.md",
    ".gitignore"
)

Write-Host "=== Packing Tun2Proxy for Android $version ==="
Write-Host "Module dir: $moduleDir"

if (Test-Path -LiteralPath $output) {
    throw "Release ZIP already exists. Increment the patch version before packaging again."
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($output, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -LiteralPath $moduleDir -Recurse -Force -File | ForEach-Object {
        $relative = $_.FullName.Substring($moduleDir.TrimEnd('\').Length + 1)
        $parts = $relative -split '[\\/]'

        # Skip if in excluded directory
        if ($parts.Length -gt 0 -and $excludeDirs -contains $parts[0]) {
            return
        }

        # Skip excluded file basenames
        if ($excludeFiles -contains $_.Name) {
            return
        }

        $entryName = ($parts -join '/')
        $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = $_.LastWriteTime
        $inputStream = [System.IO.File]::OpenRead($_.FullName)
        try {
            $entryStream = $entry.Open()
            try {
                $inputStream.CopyTo($entryStream)
            } finally {
                $entryStream.Dispose()
            }
        } finally {
            $inputStream.Dispose()
        }
    }
} finally {
    $zip.Dispose()
}

Write-Host "Package created: $output"
Write-Host "Install via: KernelSU Manager > Modules > Install from storage"
