# Lumra installer for Windows (no package manager required).
#
#   irm https://raw.githubusercontent.com/croc100/lumra/main/install.ps1 | iex
#
# Downloads the latest release, extracts lumra.exe to %LOCALAPPDATA%\Lumra, and
# adds it to the user PATH. Prefer Scoop if you have it:
#   scoop bucket add croc100 https://github.com/croc100/scoop-bucket
#   scoop install lumra

$ErrorActionPreference = 'Stop'
$repo = 'croc100/lumra'

Write-Host 'Fetching the latest Lumra release...'
$rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$tag = $rel.tag_name
$ver = $tag.TrimStart('v')

$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { throw 'Lumra requires 64-bit Windows.' }
$asset = "lumra_${ver}_windows_${arch}.zip"
$url = "https://github.com/$repo/releases/download/$tag/$asset"

$dir = Join-Path $env:LOCALAPPDATA 'Lumra'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$zip = Join-Path $env:TEMP $asset

Write-Host "Downloading $asset ..."
Invoke-WebRequest -Uri $url -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $dir -Force
Remove-Item $zip -Force

# Add to the user PATH if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your PATH."
}

Write-Host ""
Write-Host "Lumra $ver installed to $dir" -ForegroundColor Green
Write-Host "Open a NEW terminal, then run:"
Write-Host "  lumra                     # launch the dashboard (opens your browser)"
Write-Host "  lumra diagnose example.com"
Write-Host "Deep RST/TTL attribution needs an elevated (Administrator) terminal."
