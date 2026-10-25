<#
.SYNOPSIS
    Build the release artifacts and (optionally) publish a GitHub release.

.DESCRIPTION
    1. builds the setup EXE for x64 and x86 (ARM64 only on request, needs the toolchain)
    2. writes dist/SHA256SUMS.txt
    3. publishes a GitHub release with `gh` when -Publish is given, otherwise prints the
       exact commands to publish manually

.PARAMETER IncludeArm64
    Also try to build the ARM64 setup. Fails loudly if the ARM64 toolchain is missing.

.PARAMETER Publish
    Create the GitHub release with the GitHub CLI (`gh` must be installed and authenticated).

.EXAMPLE
    pwsh -File scripts/release.ps1

.EXAMPLE
    pwsh -File scripts/release.ps1 -Version 2.0.1 -Publish
#>
[CmdletBinding()]
param(
    [string]$Version = '2.0.0',

    [switch]$IncludeArm64,

    [switch]$Publish,

    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir  = Join-Path $RepoRoot 'dist'
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$archs = @('x64', 'x86')
if ($IncludeArm64) { $archs += 'arm64' }

# ------------------------------------------------------------------ 1. build installers
$built = @()
foreach ($arch in $archs) {
    if ($SkipBuild) { continue }
    Write-Host ""
    Write-Host "=== setup: $arch ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'build-installer.ps1') -Arch $arch -Version $Version
    $built += (Join-Path $DistDir ("ADCS-CDBRP-Provider-Setup-{0}-{1}.exe" -f $Version, $arch))
}

$artifacts = Get-ChildItem $DistDir -Filter "*.exe" | Where-Object { $_.Name -match [regex]::Escape($Version) }
if (-not $artifacts) { throw "no setup EXE found in $DistDir for version $Version" }

# ------------------------------------------------------------------ 2. checksums
$sums = foreach ($f in ($artifacts | Sort-Object Name)) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $hash, $f.Name
}
$sumsPath = Join-Path $DistDir 'SHA256SUMS.txt'
Set-Content -Path $sumsPath -Value $sums -Encoding ASCII

Write-Host ""
Write-Host "=== artifacts ===" -ForegroundColor Cyan
foreach ($f in ($artifacts | Sort-Object Name)) {
    Write-Host ("  {0,-46} {1,9} B" -f $f.Name, $f.Length)
}
Write-Host ("  {0,-46} {1,9} B" -f 'SHA256SUMS.txt', (Get-Item $sumsPath).Length)
Write-Host ""
Get-Content $sumsPath | ForEach-Object { Write-Host ("  " + $_) }

# ------------------------------------------------------------------ 3. release
$tag = "v$Version"
$notes = Join-Path $RepoRoot ("docs\RELEASE-NOTES-{0}.md" -f $Version)
$notesArg = $null
if (Test-Path $notes) {
    $notesArg = $notes
    Write-Host ""
    Write-Host "release notes: $notes"
} else {
    Write-Host ""
    Write-Host "release notes not found for $Version (docs\RELEASE-NOTES-$Version.md) - will use --generate-notes"
}

$assetPaths = @($artifacts | Sort-Object Name | ForEach-Object { $_.FullName }) + $sumsPath

if ($Publish) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        throw "gh (GitHub CLI) not found. Install it, or run without -Publish and upload manually."
    }
    & gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gh is not authenticated (run: gh auth login)" }

    $ghArgs = @('release', 'create', $tag, '--title', "ADCS CDBRP Provider $Version", '--latest')
    if ($notesArg) { $ghArgs += @('--notes-file', $notesArg) } else { $ghArgs += '--generate-notes' }
    $ghArgs += $assetPaths

    Write-Host ""
    Write-Host "publishing $tag ..." -ForegroundColor Cyan
    & gh @ghArgs
    if ($LASTEXITCODE -ne 0) { throw "gh release create failed (exit $LASTEXITCODE)" }
    Write-Host "release published: $tag" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "=== publish ===" -ForegroundColor Cyan
    Write-Host "Option A - GitHub CLI:"
    $assetList = ($assetPaths | ForEach-Object { '"' + $_ + '"' }) -join ' '
    if ($notesArg) {
        Write-Host ("  gh release create {0} --title `"ADCS CDBRP Provider {1}`" --notes-file `"{2}`" --latest {3}" -f $tag, $Version, $notesArg, $assetList)
    } else {
        Write-Host ("  gh release create {0} --title `"ADCS CDBRP Provider {1}`" --generate-notes --latest {2}" -f $tag, $Version, $assetList)
    }
    Write-Host ""
    Write-Host "Option B - web UI:"
    Write-Host "  1. open https://github.com/4625tracker/ADCS-CDBRP-Provider/releases/new"
    Write-Host ("  2. tag: {0}   title: ADCS CDBRP Provider {1}" -f $tag, $Version)
    Write-Host ("  3. paste the body of docs/RELEASE-NOTES-{0}.md" -f $Version)
    Write-Host "  4. attach every file from dist/ (the EXEs and SHA256SUMS.txt)"
    Write-Host ""
    Write-Host "Note: --latest on gh, or 'Set as the latest release' in the UI."
}
