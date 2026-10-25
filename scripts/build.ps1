<#
.SYNOPSIS
    Build OcspDbProvider (native COM DLL) and uitest.exe.

.DESCRIPTION
    Locates any usable Visual Studio / Build Tools installation (vswhere first, then the
    usual paths) and selects the toolchain for -Arch: x64, x86 or arm64.

.EXAMPLE
    pwsh -File scripts/build.ps1
    pwsh -File scripts/build.ps1 -Arch x86
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Arch = 'x64',

    # Output directory; default <repo>/out/<arch>
    [string]$OutDir,

    # Remove intermediate files (.obj/.res/.exp/.lib) afterwards
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SrcDir   = Join-Path $RepoRoot 'src\native'
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot "out\$Arch" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ------------------------------------------------------------------ locate vcvars
function Get-VsInstallRoots {
    $roots = @()
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        # Prefer instances that actually ship the C++ tools; -prerelease covers preview builds
        $found = & $vswhere -products * -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                            -property installationPath 2>$null
        if ($found) { $roots += $found }
        # Fall back to any instance (component ids differ between some Build Tools releases)
        $any = & $vswhere -products * -prerelease -property installationPath 2>$null
        if ($any) { $roots += $any }
    }
    foreach ($base in @("${env:ProgramFiles}\Microsoft Visual Studio", "${env:ProgramFiles(x86)}\Microsoft Visual Studio")) {
        if (-not (Test-Path $base)) { continue }
        foreach ($year in Get-ChildItem $base -Directory -ErrorAction SilentlyContinue) {
            foreach ($ed in Get-ChildItem $year.FullName -Directory -ErrorAction SilentlyContinue) {
                $roots += $ed.FullName
            }
        }
    }
    return ($roots | Where-Object { $_ } | Select-Object -Unique)
}

function Get-VcVarsPath([string]$arch) {
    $names = switch ($arch) {
        'x64'   { @('vcvars64.bat') }
        'x86'   { @('vcvarsamd64_x86.bat', 'vcvars32.bat', 'vcvarsx86.bat') }
        'arm64' { @('vcvarsamd64_arm64.bat', 'vcvarsx86_arm64.bat', 'vcvarsarm64.bat') }
    }
    foreach ($root in Get-VsInstallRoots) {
        $dir = Join-Path $root 'VC\Auxiliary\Build'
        foreach ($n in $names) {
            $p = Join-Path $dir $n
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

$vcvars = Get-VcVarsPath $Arch
if (-not $vcvars) {
    if ($Arch -eq 'arm64') {
        $hint = "ARM64 target tools are missing. Install the optional component " +
                "'MSVC v14x - C++ ARM64 build tools' in the Visual Studio Installer."
    } else {
        $hint = "Install Visual Studio 2019/2022 (or Build Tools) with the " +
                "'Desktop development with C++' workload."
    }
    throw "No vcvars script found for $Arch. $hint"
}
Write-Host "vcvars : $vcvars"

# ------------------------------------------------------------------ compile
$machine = @{ x64 = 'X64'; x86 = 'X86'; arm64 = 'ARM64' }[$Arch]
$dll  = Join-Path $OutDir 'OcspDbProvider.dll'
$res  = Join-Path $OutDir 'OcspDbProvider.res'
$uit  = Join-Path $OutDir 'uitest.exe'
$cfg  = Join-Path $OutDir 'OcspConfig.exe'
$cfgRes = Join-Path $OutDir 'OcspConfig.res'

$cmd = @(
    ('call "' + $vcvars + '" >nul'),
    ('cd /d "' + $SrcDir + '"'),
    ('rc /nologo /fo "' + $res + '" OcspDbProvider.rc'),
    ('rc /nologo /fo "' + $cfgRes + '" OcspConfig.rc'),
    ('cl /nologo /LD /EHsc /O2 /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE ' +
     '/D_WIN32_WINNT=0x0601 OcspDbProvider.cpp OcspDbConfig.cpp ' +
     '/link /DEF:OcspDbProvider.def /SUBSYSTEM:WINDOWS /MACHINE:' + $machine + ' /OUT:"' + $dll + '" "' + $res + '" ' +
     'ole32.lib oleaut32.lib advapi32.lib user32.lib comdlg32.lib gdi32.lib'),
    ('cl /nologo /EHsc /O2 /W3 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /Fe:"' + $uit + '" uitest.cpp ' +
     '/link /MACHINE:' + $machine + ' ole32.lib oleaut32.lib user32.lib'),
    ('cl /nologo /EHsc /O2 /W3 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 ' +
     'OcspConfig.cpp OcspDbConfig.cpp "' + $cfgRes + '" ' +
     '/link /SUBSYSTEM:WINDOWS /MACHINE:' + $machine + ' /OUT:"' + $cfg + '" ' +
     'comdlg32.lib advapi32.lib user32.lib shell32.lib gdi32.lib')
) -join ' && '

Write-Host "--- building $Arch"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "build failed with exit code $LASTEXITCODE" }

foreach ($f in @($dll, $uit, $cfg)) {
    if (-not (Test-Path $f)) { throw "missing output: $f" }
}

# ------------------------------------------------------------------ verify exports
$dumpbin = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
    $root = & $vswhere -products * -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1
    if ($root) {
        $bin = Get-ChildItem (Join-Path $root 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($bin) {
            $cand = Join-Path $bin.FullName "bin\Hostx64\$Arch\dumpbin.exe"
            if (-not (Test-Path $cand)) { $cand = Join-Path $bin.FullName 'bin\Hostx64\x64\dumpbin.exe' }
            if (Test-Path $cand) { $dumpbin = $cand }
        }
    }
}

$required = @('DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer', 'DllUnregisterServer')
if ($dumpbin) {
    $exports = & $dumpbin /nologo /exports $dll 2>$null
    $missing = $required | Where-Object { -not ($exports -match ("\b" + $_ + "\b")) }
    if ($missing) { throw "missing exports: $($missing -join ', ')" }
    Write-Host "exports: $($required -join ', ') OK"
} else {
    Write-Host 'exports: (dumpbin not found, skipped)'
}

foreach ($f in @($dll, $uit)) {
    $h = Get-FileHash $f -Algorithm SHA256
    Write-Host ('built : {0,-24} {1,9} B  sha256={2}' -f (Split-Path $f -Leaf), (Get-Item $f).Length, $h.Hash.Substring(0, 16))
}
Write-Host "out   : $OutDir"

if ($Clean) {
    # cl writes .obj/.lib/.exp next to the sources (cwd), the linker output is in $OutDir
    Get-ChildItem $SrcDir -Include '*.obj', '*.lib', '*.exp', '*.res' -File | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem $OutDir -Include '*.obj', '*.exp', '*.lib', '*.res' -File | Remove-Item -Force -ErrorAction SilentlyContinue
}
