<#
.SYNOPSIS
    Export a CA database snapshot (revdb.dat) consumed by OcspDbProvider.

.DESCRIPTION
    Runs `certutil -view` against the CA database and writes the tab-separated snapshot:

        <serial> \t <disposition> \t <revokedWhen FILETIME> \t <reason> \t <notAfter FILETIME>

    Parsing is shape based (not label based), so it works on localized certutil output.

    The file is written atomically (temp file + replace), so the provider never reads a
    half-written snapshot.

.EXAMPLE
    pwsh -File scripts/sync.ps1 -CA 'SERVER\CORP-CA'

.EXAMPLE
    pwsh -File scripts/sync.ps1 -CA 'SERVER\CORP-CA' -Out 'C:\ProgramData\OcspDbProvider\data\revdb.dat'
#>
[CmdletBinding()]
param(
    # CA config string. Empty = whatever certutil picks for the local CA.
    [string]$CA = '',

    # Snapshot output path. Empty = <DataDir>\<safe-ca-name>.dat
    [string]$Out = '',

    [string]$DataDir = (Join-Path $env:ProgramData 'OcspDbProvider\data'),

    [string]$CertUtil = 'certutil.exe',

    # Do not write anything; print what would be written
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Same sanitization as SafeFileName() in OcspDbProvider.cpp
function ConvertTo-SafeName([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return 'default' }
    $out = [System.Text.StringBuilder]::new()
    foreach ($ch in $s.ToCharArray()) {
        if (($ch -match '[A-Za-z0-9._-]')) { [void]$out.Append($ch) } else { [void]$out.Append('_') }
    }
    $name = $out.ToString()
    if ([string]::IsNullOrEmpty($name)) { return 'default' }
    return $name
}

# certutil needs HOST\CA-NAME; a bare CA name fails with RPC_S_SERVER_UNAVAILABLE (0x800706BA)
if (-not [string]::IsNullOrEmpty($CA) -and $CA -notmatch '\\') {
    $CA = $env:COMPUTERNAME + '\' + $CA
}

if ([string]::IsNullOrEmpty($Out)) {
    $Out = Join-Path $DataDir ((ConvertTo-SafeName $CA) + '.dat')
}
$OutDir = Split-Path -Parent $Out
if (-not $DryRun -and -not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
$logPath = if ($DataDir) { Join-Path (Split-Path -Parent $Out) 'sync.log' } else { Join-Path $OutDir 'sync.log' }

function Write-SyncLog([string]$msg) {
    $line = ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg)
    Write-Verbose $line
    if (-not $DryRun) {
        Add-Content -Path $logPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ run certutil
$viewArgs = @('-view', '-silent', '-out', 'SerialNumber,Disposition,RevokedWhen,RevokedReason,NotAfter')
if (-not [string]::IsNullOrEmpty($CA)) { $viewArgs = @('-view', '-silent', '-config', $CA, '-out', 'SerialNumber,Disposition,RevokedWhen,RevokedReason,NotAfter') }

Write-SyncLog ("certutil " + ($viewArgs -join ' '))
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $CertUtil
# ArgumentList does not exist on Windows PowerShell 5.1 (.NET Framework), where it is $null,
# so build a quoted argument string instead.
$psi.Arguments = ($viewArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
# certutil writes in the OEM code page; decode explicitly instead of guessing
try { $psi.StandardOutputEncoding = [System.Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage) } catch { }

$proc = [System.Diagnostics.Process]::Start($psi)
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
[void]$proc.WaitForExit(120000)
if (-not $proc.HasExited) { $proc.Kill(); throw 'certutil timed out after 120s' }
if ($proc.ExitCode -ne 0) {
    Write-SyncLog ("certutil failed: exit=$($proc.ExitCode) stderr=$stderr")
    throw "certutil failed (exit $($proc.ExitCode)): $stderr"
}

# ------------------------------------------------------------------ parse
$reQuoted = [regex]'"([0-9a-fA-F]{6,})"'
$reDisp   = [regex]'0x([0-9a-fA-F]+)\s*\((\d+)\)'
$reHexNum = [regex]'0x([0-9a-fA-F]+)'
$reDate   = [regex]'(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?'

function ConvertTo-FileTimeUtc([datetime]$dt) {
    try { return $dt.ToUniversalTime().ToFileTimeUtc() } catch { return 0 }
}

$rows = [System.Collections.Generic.List[string]]::new()
$curSerial = $null
$curDisp = -1
$curRevoked = 0
$curReason = 0
$curNotAfter = 0
$seenDisp = $false

function Flush-Row {
    if ($null -ne $script:curSerial -and $script:curDisp -ge 0) {
        $script:rows.Add(("{0}`t{1}`t{2}`t{3}`t{4}" -f $script:curSerial, $script:curDisp,
                          $script:curRevoked, $script:curReason, $script:curNotAfter))
    }
    $script:curSerial = $null
    $script:curDisp = -1
    $script:curRevoked = 0
    $script:curReason = 0
    $script:curNotAfter = 0
    $script:seenDisp = $false
}

foreach ($raw in ($stdout -split "`n")) {
    $line = $raw.TrimEnd("`r")
    $mq = $reQuoted.Match($line)
    if ($mq.Success) {
        Flush-Row
        $curSerial = $mq.Groups[1].Value
        continue
    }
    if ($null -eq $curSerial) { continue }

    if (-not $seenDisp) {
        $md = $reDisp.Match($line)
        if ($md.Success) {
            $curDisp = [int]$md.Groups[2].Value
            $seenDisp = $true
            continue
        }
    }

    $mdate = $reDate.Match($line)
    if ($mdate.Success) {
        $sec = if ($mdate.Groups[6].Success) { [int]$mdate.Groups[6].Value } else { 0 }
        $dt = [datetime]::new([int]$mdate.Groups[1].Value, [int]$mdate.Groups[2].Value,
                              [int]$mdate.Groups[3].Value, [int]$mdate.Groups[4].Value,
                              [int]$mdate.Groups[5].Value, $sec)
        if ($curDisp -eq 21 -and $curRevoked -eq 0) { $curRevoked = ConvertTo-FileTimeUtc $dt }
        elseif ($curNotAfter -eq 0) { $curNotAfter = ConvertTo-FileTimeUtc $dt }
        continue
    }

    $mh = $reHexNum.Match($line)
    if ($mh.Success -and -not $reDisp.IsMatch($line) -and $curDisp -eq 21 -and $curReason -eq 0) {
        $curReason = [Convert]::ToInt32($mh.Groups[1].Value, 16)
    }
}
Flush-Row

if ($rows.Count -eq 0) {
    Write-SyncLog 'no rows parsed from certutil output'
    throw 'no rows parsed; check -CA / certutil permissions (CA_ACCESS_READ)'
}

# ------------------------------------------------------------------ write atomically
$header = @(
    '# OcspDbProvider snapshot - generated by scripts/sync.ps1, do not edit by hand',
    ('# ca         : ' + $(if ($CA) { $CA } else { '(local)' })),
    ('# generated  : ' + (Get-Date -Format 'u')),
    '# columns    : serial <TAB> disposition <TAB> revokedWhen(FILETIME) <TAB> reason <TAB> notAfter(FILETIME)'
)
$body = $header + $rows

if ($DryRun) {
    Write-Host ("[dry-run] would write {0} rows to {1}" -f $rows.Count, $Out)
    $body | Select-Object -First 8 | ForEach-Object { Write-Host $_ }
    return
}

$tmp = $Out + '.tmp'
Set-Content -Path $tmp -Value $body -Encoding ASCII
Move-Item -Path $tmp -Destination $Out -Force
Write-SyncLog ("wrote {0} rows -> {1}" -f $rows.Count, $Out)
Write-Host ("snapshot: {0} rows -> {1}" -f $rows.Count, $Out)
