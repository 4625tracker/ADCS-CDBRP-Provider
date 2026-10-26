<#
.SYNOPSIS
    Local self-check for a built provider: resources, COM contract, snapshot lookup.

.DESCRIPTION
    Runs entirely without administrator rights and without touching the registry or the
    running responder:

      1. builds the DLL (unless -SkipBuild)
      2. rescheck  - both localized dialogs and the version resource exist
      3. info      - GetProviderInformation / GetStatus return the expected shapes
      4. verify    - a synthetic snapshot drives good / revoked / unknown answers

    Fixtures are created under -WorkDir (default <repo>/_test) and removed afterwards
    unless -KeepFixtures is given.

.EXAMPLE
    pwsh -File scripts/test.ps1

.EXAMPLE
    pwsh -File scripts/test.ps1 -Arch x86 -SkipBuild
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Arch = 'x64',

    [switch]$SkipBuild,

    [string]$WorkDir,

    [switch]$KeepFixtures
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $WorkDir) { $WorkDir = Join-Path $RepoRoot '_test' }
$InstallDir = Join-Path $WorkDir 'install'
$DataDir    = Join-Path $InstallDir 'data'
$LogFile    = Join-Path $WorkDir 'run.txt'

$script:pass = 0
$script:fail = 0

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) { $script:pass++; Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green }
    else     { $script:fail++; Write-Host ("  FAIL  {0}  {1}" -f $name, $detail) -ForegroundColor Red }
}

function Invoke-Uitest([string]$argLine) {
    $exe = Join-Path $RepoRoot ("out\$Arch\uitest.exe")
    $cmd = '"{0}" {1} -dll "{2}" -ca "TEST\CA" > "{3}" 2>&1' -f $exe, $argLine, $Dll, $LogFile
    # A freshly built unsigned exe can be locked by antivirus for a few seconds; cmd then
    # writes its complaint (localised!) into the log and the assertion fails for no real
    # reason. Match the English and Chinese wording, and retry long enough for a scan to end.
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        if (Test-Path $LogFile) { Remove-Item $LogFile -Force -ErrorAction SilentlyContinue }
        cmd /c $cmd | Out-Null
        if (-not (Test-Path $LogFile)) { Start-Sleep -Milliseconds 500; continue }
        $text = Get-Content $LogFile -Encoding UTF8 -Raw
        if ([string]::IsNullOrWhiteSpace($text)) { Start-Sleep -Milliseconds 500; continue }
        if ($text -match 'Access is denied|cannot find the file|拒绝访问|找不到') {
            Start-Sleep -Milliseconds 500
            continue
        }
        return $text
    }
    return ''
}

# ------------------------------------------------------------------ build
if (-not $SkipBuild) {
    Write-Host '=== build' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'build.ps1') -Arch $Arch
}

$Dll = Join-Path $RepoRoot ("out\$Arch\OcspDbProvider.dll")
$Uit = Join-Path $RepoRoot ("out\$Arch\uitest.exe")
if (-not (Test-Path $Dll)) { throw "missing $Dll (run without -SkipBuild)" }

# ------------------------------------------------------------------ fixtures
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$ftRevoked = ([datetime]::SpecifyKind([datetime]'2026-10-08T13:30:00', 'Utc')).ToFileTimeUtc()
$ftNotAfter = ([datetime]::SpecifyKind([datetime]'2046-10-08T19:38:00', 'Utc')).ToFileTimeUtc()
$revokedSerial = '6200000003CC4141256F50414D000000000003'
$validSerial   = '1BB4C8FDB13FF1AD40B36BB38899571D'

Set-Content (Join-Path $DataDir 'TEST_CA.dat') @(
    '# serial <TAB> disposition <TAB> revokedWhen <TAB> reason <TAB> notAfter',
    ("{0}`t21`t{1}`t1`t{2}" -f $revokedSerial, $ftRevoked, $ftNotAfter),
    ("{0}`t20`t0`t0`t{1}" -f $validSerial, $ftNotAfter)
) -Encoding ASCII

# Per-CA override: unknown maps to 9 so a miss is distinguishable from "valid"
$ini = @(
    '[default]'
    'checkseconds=0'
    'validstatus=0'
    'revokedstatus=1'
    'unknownstatus=0'
    ''
    '[ca:TEST\CA]'
    ('snapshot=' + (Join-Path $DataDir 'TEST_CA.dat'))
    'unknownstatus=9'
)
[System.IO.File]::WriteAllLines((Join-Path $InstallDir 'provider.ini'), $ini, (New-Object System.Text.UTF8Encoding($false)))

$env:OCSPDBPROVIDER_DIR = $InstallDir

# ------------------------------------------------------------------ 1. resources
Write-Host '=== resources' -ForegroundColor Cyan
$out = cmd /c ('"{0}" rescheck -dll "{1}" 2>&1' -f $Uit, $Dll)
$txt = $out -join "`n"
Check 'IDD_CONFIG_ZH present' ($txt -match 'IDD_CONFIG_ZH .*caption=') $txt
Check 'IDD_CONFIG_EN present' ($txt -match 'IDD_CONFIG_EN .*caption=') $txt
Check 'VERSIONINFO present'   ($txt -match 'VERSIONINFO: present') $txt

# ------------------------------------------------------------------ 2. provider info
Write-Host '=== provider information' -ForegroundColor Cyan
$out = Invoke-Uitest 'info -lang en'
Check 'GetProviderInformation S_OK' ($out -match 'GetProviderInformation hr=0x00000000') $out
Check 'English name'                ($out -match 'name: CA Database Revocation Provider') $out
Check 'GetStatus returns string[]'  ($out -match 'vt=0x2008') $out
Check 'status reports 2 entries'    ($out -match 'Snapshot entries: 2') $out

$out = Invoke-Uitest 'info -lang zh'
Check 'Chinese name differs from English' (($out -match 'name: .+') -and ($out -notmatch 'name: CA Database Revocation Provider')) $out
Check 'Chinese status lines' ($out -match 'status\[0\]: CA') $out

# ------------------------------------------------------------------ 3. lookups
Write-Host '=== serial lookups' -ForegroundColor Cyan
$out = Invoke-Uitest ("verify {0}" -f $revokedSerial)
Check 'revoked serial -> status 1' ($out -match 'status=1') $out
Check 'revoked reason propagated'  ($out -match 'reason=1') $out
# nextUpdate decides how long the responder may serve a cached answer. If this drifts back to
# minutes, revocation stops showing up "within a minute" no matter how fresh the snapshot is.
Check 'response window is 60s (cache lifetime)' ($out -match 'window=60') $out

$out = Invoke-Uitest ("verify {0}" -f $validSerial)
Check 'valid serial -> status 0' ($out -match 'status=0') $out

$out = Invoke-Uitest 'verify DEADBEEF00000000000000000000000000000001'
Check 'unknown serial -> per-CA unknown (9)' ($out -match 'status=9') $out

# Leading zeros must not change the answer (serial normalization)
$out = Invoke-Uitest ("verify 00{0}" -f $validSerial)
Check 'leading-zero serial still matches' ($out -match 'status=0') $out

# ------------------------------------------------------------------ 4. multi-CA config tool
Write-Host '=== multi-CA config tool' -ForegroundColor Cyan
$cfgExe = Join-Path $RepoRoot ("out\$Arch\OcspConfig.exe")
$cfgDir = Join-Path $WorkDir 'cfg'
$cfgData = Join-Path $cfgDir 'data'
New-Item -ItemType Directory -Force -Path $cfgData | Out-Null
Copy-Item (Join-Path $DataDir 'TEST_CA.dat') (Join-Path $cfgData 'a.dat') -Force
Set-Content (Join-Path $cfgData 'b.dat') @(
    '# b',
    ("AAAA1111BBBB2222`t21`t{0}`t4`t{1}" -f $ftRevoked, $ftNotAfter)
) -Encoding ASCII

$savedEnv = $env:OCSPDBPROVIDER_DIR
$env:OCSPDBPROVIDER_DIR = $cfgDir
$dumpFile = Join-Path $WorkDir 'cfg-dump.txt'

function Invoke-Cfg([string[]]$argv) {
    # OcspConfig is a GUI-subsystem binary: cmd /c would return before it finished, so wait
    # for the process and let Start-Process own the redirection handles. Same antivirus-lock
    # retry as Invoke-Uitest, because Start-Process throws instead of writing a log.
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            $null = Start-Process -FilePath $cfgExe -ArgumentList $argv -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput $dumpFile -RedirectStandardError "$dumpFile.err" -ErrorAction Stop
            if (Test-Path $dumpFile) { return (Get-Content $dumpFile -Encoding UTF8 -Raw) }
            return ''
        } catch {
            if ($attempt -eq 20) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
    return ''
}

$null = Invoke-Cfg @('--set', 'CORP-A', '--snapshot', (Join-Path $cfgData 'a.dat'), '--check', '0', '--unknown', '5')
$null = Invoke-Cfg @('--set', 'CORP-B', '--snapshot', (Join-Path $cfgData 'b.dat'), '--unknown', '7')

$out = Invoke-Cfg @('--dump')
Check 'config tool: both CAs listed'      (($out -match 'CORP-A') -and ($out -match 'CORP-B')) $out
Check 'config tool: CA A rows and codes'  ($out -match 'CORP-A\s+ini\s+0\s+0\s+1\s+5\s+2\s') $out
Check 'config tool: CA B rows and codes'  ($out -match 'CORP-B\s+ini\s+2\s+0\s+1\s+7\s+1\s') $out

# A partial --set must keep the other fields
$null = Invoke-Cfg @('--set', 'CORP-A', '--unknown', '9')
$out = Invoke-Cfg @('--dump')
Check 'config tool: partial update keeps other fields' ($out -match 'CORP-A\s+ini\s+0\s+0\s+1\s+9\s+2\s') $out

# The provider must read exactly what the tool wrote
$verifyOut = Join-Path $WorkDir 'verify.txt'
cmd /c ('"{0}" verify DEADBEEF00000000000000000000000000000001 -dll "{1}" -ca CORP-A > "{2}" 2>&1' -f $Uit, $Dll, $verifyOut) | Out-Null
$out = if (Test-Path $verifyOut) { Get-Content $verifyOut -Encoding UTF8 -Raw } else { '' }
Check 'provider reads tool-written config (unknown=9)' ($out -match 'status=9') $out

$out = Invoke-Cfg @('--remove', 'CORP-B')
$out = Invoke-Cfg @('--dump')
Check 'config tool: removed CA disappears' (-not ($out -match 'CORP-B')) $out

$env:OCSPDBPROVIDER_DIR = $savedEnv

# ------------------------------------------------------------------ summary
if (-not $KeepFixtures) { Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ''
if ($script:fail -eq 0) {
    Write-Host ("=== all {0} checks passed ===" -f $script:pass) -ForegroundColor Green
    exit 0
} else {
    Write-Host ("=== {0} passed, {1} FAILED ===" -f $script:pass, $script:fail) -ForegroundColor Red
    exit 1
}
