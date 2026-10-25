<#
.SYNOPSIS
    Install / activate / uninstall the OCSP CA-database revocation provider.

.DESCRIPTION
    The provider is a native COM in-proc server loaded by the AD CS Online Responder
    (OCSPSvc). Installation copies the DLL into an install directory, registers it with
    regsvr32, writes provider.ini, generates the first snapshot and registers a scheduled
    task that refreshes it every minute.

    Activation switches the responder's ProviderCLSID to this provider; deactivation puts
    the built-in CRL provider back. Both are reversible and a rollback file is written.

    Default install directory: %ProgramData%\OcspDbProvider
    (override with -InstallDir or the OCSPDBPROVIDER_DIR environment variable).

.PARAMETER Mode
    install     build + copy + register + config + first snapshot + scheduled task
    activate    point the responder at this provider and restart the service
    deactivate  restore the built-in CRL provider
    uninstall   stop, unregister, remove the task (add -RemoveFiles to delete the files)
    status      show service state, provider CLSID, snapshot rows, task state, log tail
    sync        refresh the snapshot now
    selftest    run uitest.exe against the installed DLL (no MMC needed)

.EXAMPLE
    pwsh -File scripts/install.ps1 -Mode install

.EXAMPLE
    pwsh -File scripts/install.ps1 -Mode install -CAConfig 'SRV1\CORP-CA' -Arch x64

.EXAMPLE
    pwsh -File scripts/install.ps1 -Mode activate
#>
[CmdletBinding()]
param(
    [ValidateSet('install', 'activate', 'deactivate', 'uninstall', 'status', 'sync', 'selftest')]
    [string]$Mode = 'install',

    [string]$InstallDir = (Join-Path $env:ProgramData 'OcspDbProvider'),

    # CA name or HOST\CA-NAME. Empty = auto-detect from the responder registry.
    [string]$CAConfig = '',

    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Arch = 'x64',

    # Rebuild even if the DLL already exists
    [switch]$Rebuild,

    # Remove the install directory during -Mode uninstall
    [switch]$RemoveFiles,

    # Optional: existing 1.x provider directory to migrate a snapshot/config from.
    # Nothing is assumed by default; pass it explicitly, e.g. -MigrationSource 'D:\old\ocsp'
    [string]$MigrationSource = ''
)

$ErrorActionPreference = 'Stop'

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$ProviderCLSID = '{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}'
$BuiltinCLSID  = '{4956d17f-88fd-4198-b287-1e6e65883b19}'   # ocsprevp.dll (CRL)
$ResponderRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder'
$ServiceName   = 'OCSPSvc'
$PoolName      = 'OCSPISAPIAppPool'
$DllPath       = Join-Path $InstallDir 'OcspDbProvider.dll'
$IniPath       = Join-Path $InstallDir 'provider.ini'
$DataDir       = Join-Path $InstallDir 'data'
$BackupPath    = Join-Path $InstallDir 'rollback.txt'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step($msg) { Write-Host "--- $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

function Get-ResponderCAs {
    if (-not (Test-Path $ResponderRoot)) { return @() }
    return @(Get-ChildItem $ResponderRoot -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
}

# The responder may pass either "CA-NAME" or "HOST\CA-NAME" to the provider, so both
# spellings are written as separate [ca:...] sections pointing at the same snapshot.
function Get-CaIdCandidates([string]$ca) {
    if ([string]::IsNullOrEmpty($ca)) { return @() }
    $set = New-Object System.Collections.Generic.List[string]
    $set.Add($ca)
    if ($ca -notmatch '\\') {
        $set.Add(($env:COMPUTERNAME + '\' + $ca))
    } else {
        $set.Add(($ca.Split('\')[-1]))
    }
    return ($set | Select-Object -Unique)
}

function ConvertTo-SafeName([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return 'default' }
    $out = [System.Text.StringBuilder]::new()
    foreach ($ch in $s.ToCharArray()) {
        if ($ch -match '[A-Za-z0-9._-]') { [void]$out.Append($ch) } else { [void]$out.Append('_') }
    }
    $name = $out.ToString()
    if ([string]::IsNullOrEmpty($name)) { return 'default' }
    return $name
}

function Resolve-CA {
    if (-not [string]::IsNullOrEmpty($CAConfig)) { return $CAConfig }
    $cas = Get-ResponderCAs
    if ($cas.Count -eq 0) { return '' }
    if ($cas.Count -eq 1) { return $cas[0] }
    throw ("multiple CA responder configs found: " + ($cas -join ', ') + ". Pass -CAConfig explicitly.")
}

# The registry key is the bare CA name, but certutil needs HOST\CA-NAME; a bare name fails
# with RPC_S_SERVER_UNAVAILABLE (0x800706BA).
function Get-CaConfigString([string]$ca) {
    if ([string]::IsNullOrEmpty($ca)) { return '' }
    if ($ca -match '\\') { return $ca }
    return ($env:COMPUTERNAME + '\' + $ca)
}

function Stop-OcspStack {
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    if (Get-Command Stop-WebAppPool -ErrorAction SilentlyContinue) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Stop-WebAppPool -Name $PoolName -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.CommandLine -match [regex]::Escape($PoolName)) {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Start-OcspStack {
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Start-Service $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    if (Get-Command Start-WebAppPool -ErrorAction SilentlyContinue) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Start-WebAppPool -Name $PoolName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

function Get-ProviderClsid([string]$ca) {
    $p = Join-Path (Join-Path $ResponderRoot $ca) 'ProviderCLSID'
    return (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).ProviderCLSID
}

function Write-Ini([string]$ca) {
    if (Test-Path $IniPath) { Write-Ok "$IniPath (kept)"; return }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# OcspDbProvider configuration (written by scripts/install.ps1)')
    $lines.Add('# [default] applies to every CA, [ca:<ca-id>] overrides one responder.')
    $lines.Add('# Cache lifetime in seconds; 0 = re-check the snapshot on every query.')
    $lines.Add('[default]')
    $lines.Add('checkseconds=2')
    $lines.Add('validstatus=0')
    $lines.Add('revokedstatus=1')
    $lines.Add('unknownstatus=0')

    if (-not [string]::IsNullOrEmpty($ca)) {
        $snap = Join-Path $DataDir ((ConvertTo-SafeName $ca) + '.dat')
        foreach ($id in (Get-CaIdCandidates $ca)) {
            $lines.Add('')
            $lines.Add('[ca:' + $id + ']')
            $lines.Add('snapshot=' + $snap)
        }
    }
    [System.IO.File]::WriteAllLines($IniPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok $IniPath
}

function Invoke-Migration {
    if ([string]::IsNullOrEmpty($MigrationSource)) { return }
    if (-not (Test-Path -LiteralPath $MigrationSource)) {
        Write-Warn2 ("migration source not found: " + $MigrationSource)
        return
    }
    $legacyIni = Join-Path $MigrationSource 'provider.ini'
    $legacySnap = Join-Path $MigrationSource 'revdb.dat'
    if (-not (Test-Path $legacyIni) -and -not (Test-Path $legacySnap)) { return }
    if (Test-Path $IniPath) { return }

    Write-Step "migrating from $MigrationSource"
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $target = Join-Path $DataDir 'revdb.dat'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# OcspDbProvider configuration (migrated from ' + $MigrationSource + ')')
    $lines.Add('[default]')

    $map = @{ 'checkseconds' = 'checkseconds'; 'validstatus' = 'validstatus';
              'revokedstatus' = 'revokedstatus'; 'unknownstatus' = 'unknownstatus' }
    if (Test-Path $legacyIni) {
        foreach ($line in (Get-Content $legacyIni)) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*)$') {
                $k = $Matches[1].ToLowerInvariant(); $v = $Matches[2].Trim()
                if ($map.ContainsKey($k)) { $lines.Add($k + '=' + $v) }
            }
        }
    }
    if (-not ($lines | Where-Object { $_ -match '^checkseconds=' })) { $lines.Add('checkseconds=2') }
    if (-not ($lines | Where-Object { $_ -match '^validstatus=' }))   { $lines.Add('validstatus=0') }
    if (-not ($lines | Where-Object { $_ -match '^revokedstatus=' })) { $lines.Add('revokedstatus=1') }
    if (-not ($lines | Where-Object { $_ -match '^unknownstatus=' })) { $lines.Add('unknownstatus=0') }
    if (Test-Path $legacySnap) {
        Copy-Item $legacySnap $target -Force
        $lines.Add('snapshot=' + $target)
        Write-Ok ("snapshot copied -> " + $target)
    }
    [System.IO.File]::WriteAllLines($IniPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok ("config migrated -> " + $IniPath)
}

function Invoke-Sync([string]$ca) {
    Write-Step 'snapshot'
    $syncScript = Join-Path $PSScriptRoot 'sync.ps1'
    $out = Join-Path $DataDir ((ConvertTo-SafeName $ca) + '.dat')
    # Invoke in-process (same PowerShell session) so no specific host executable is assumed
    if ([string]::IsNullOrEmpty($ca)) {
        & $syncScript -Out $out -DataDir $DataDir
    } else {
        & $syncScript -CA $ca -Out $out -DataDir $DataDir
    }
    if (Test-Path $out) {
        $rows = (Get-Content $out | Where-Object { $_ -and $_[0] -ne '#' }).Count
        Write-Ok ("{0} rows={1}" -f $out, $rows)
    }
}

function Register-Task([string]$ca) {
    $taskName = 'OcspDbProvider-Sync'
    if (-not [string]::IsNullOrEmpty($ca)) { $taskName += '-' + (ConvertTo-SafeName $ca) }
    Write-Step "scheduled refresh: $taskName (every minute, SYSTEM)"

    $syncScript = Join-Path $InstallDir 'sync.ps1'
    $out = Join-Path $DataDir ((ConvertTo-SafeName $ca) + '.dat')
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $syncScript + '" -Out "' + $out + '" -DataDir "' + $DataDir + '"'
    if (-not [string]::IsNullOrEmpty($ca)) { $argLine += ' -CA "' + $ca + '"' }

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    $t = Get-ScheduledTask -TaskName $taskName
    Write-Ok ("{0} state={1}" -f $t.TaskName, $t.State)
}

# ------------------------------------------------------------------ modes
switch ($Mode) {

    'install' {
        if (-not (Test-Admin)) { throw 'install requires an elevated (administrator) PowerShell.' }

        $ca = Resolve-CA
        $caConfig = Get-CaConfigString $ca
        if ([string]::IsNullOrEmpty($ca)) {
            Write-Warn2 'no OCSP responder CA found; snapshot must be produced manually (see -Mode sync -CAConfig).'
        } else {
            Write-Ok ("CA config: " + $caConfig)
        }

        Write-Step 'build'
        if ($Rebuild -or -not (Test-Path (Join-Path $RepoRoot "out\$Arch\OcspDbProvider.dll"))) {
            & (Join-Path $PSScriptRoot 'build.ps1') -Arch $Arch
        } else {
            Write-Ok 'using existing build (pass -Rebuild to force)'
        }

        Write-Step "install dir: $InstallDir"
        New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null

        # The DLL may be loaded by the running responder; stop it before replacing the file.
        Stop-OcspStack
        Copy-Item (Join-Path $RepoRoot "out\$Arch\OcspDbProvider.dll") $DllPath -Force
        Copy-Item (Join-Path $RepoRoot "out\$Arch\uitest.exe") (Join-Path $InstallDir 'uitest.exe') -Force
        Copy-Item (Join-Path $PSScriptRoot 'sync.ps1') (Join-Path $InstallDir 'sync.ps1') -Force
        Write-Ok ($DllPath + '  ' + (Get-Item $DllPath).Length + ' B')

        Write-Step 'register COM (regsvr32)'
        & regsvr32.exe /s $DllPath
        if ($LASTEXITCODE -ne 0) { throw "regsvr32 failed (exit $LASTEXITCODE) - run elevated" }
        $ip = Get-ItemProperty ('HKLM:\SOFTWARE\Classes\CLSID\' + $ProviderCLSID + '\InprocServer32') -ErrorAction SilentlyContinue
        if (-not $ip -or $ip.'(default)' -ne $DllPath) { throw "InprocServer32 mismatch: $($ip.'(default)')" }
        Write-Ok ("InprocServer32 = " + $ip.'(default)' + "  ThreadingModel=" + $ip.ThreadingModel)

        Write-Step 'permissions'
        foreach ($p in @($InstallDir, $DataDir)) {
            & icacls.exe $p /grant 'NETWORK SERVICE:(OI)(CI)(RX)' | Out-Null
        }
        Write-Ok 'NETWORK SERVICE RX granted on install dir'

        Invoke-Migration
        Write-Ini $caConfig

        if (-not [string]::IsNullOrEmpty($caConfig)) {
            try { Invoke-Sync $caConfig } catch { Write-Warn2 ("snapshot not generated: " + $_.Exception.Message) }
            Register-Task $caConfig
        }
        if ([string]::IsNullOrEmpty($MigrationSource)) {
            Write-Host '    (no -MigrationSource given: existing 1.x config was not imported)'
        }

        Start-OcspStack
        Write-Host ''
        Write-Host '=== installed (responder NOT switched yet) ===' -ForegroundColor Green
        Write-Host "    next:  pwsh -File scripts/install.ps1 -Mode activate"
    }

    'activate' {
        if (-not (Test-Admin)) { throw 'activate requires an elevated (administrator) PowerShell.' }
        $ca = Resolve-CA
        if ([string]::IsNullOrEmpty($ca)) { throw 'no CA responder config found; pass -CAConfig' }
        $key = Join-Path (Join-Path $ResponderRoot $ca) 'ProviderCLSID'
        if (-not (Test-Path (Split-Path $key -Parent))) { throw "responder config not found: $ca" }

        $cur = Get-ProviderClsid $ca
        Write-Step "activate $ca"
        Write-Ok ("current ProviderCLSID = " + $cur)

        if (-not (Test-Path $BackupPath)) {
            $lines = @('ProviderCLSID=' + $cur)
            $provPath = Join-Path (Join-Path $ResponderRoot $ca) 'Provider'
            if (Test-Path $provPath) {
                $pk = Get-ItemProperty $provPath
                foreach ($n in $pk.PSObject.Properties.Name) {
                    if ($n -notmatch '^PS') { $lines += ('Provider\' + $n + '=' + $pk.$n) }
                }
            }
            Set-Content -Path $BackupPath -Value $lines -Encoding ASCII
            Write-Ok ("backup -> " + $BackupPath)
        }

        Set-ItemProperty -Path $key -Name 'ProviderCLSID' -Value $ProviderCLSID
        $provDir = Join-Path (Join-Path $ResponderRoot $ca) 'Provider'
        if (-not (Test-Path $provDir)) { New-Item -ItemType Directory -Force -Path $provDir | Out-Null }

        Stop-OcspStack
        Start-OcspStack
        Write-Ok ("new ProviderCLSID = " + (Get-ProviderClsid $ca))
        Write-Host ''
        Write-Host '=== activated (data source = CA database snapshot) ===' -ForegroundColor Green
        Write-Host "    rollback: pwsh -File scripts/install.ps1 -Mode deactivate"
    }

    'deactivate' {
        if (-not (Test-Admin)) { throw 'deactivate requires an elevated (administrator) PowerShell.' }
        $ca = Resolve-CA
        if ([string]::IsNullOrEmpty($ca)) { throw 'no CA responder config found; pass -CAConfig' }
        $key = Join-Path (Join-Path $ResponderRoot $ca) 'ProviderCLSID'

        $target = $BuiltinCLSID
        if (Test-Path $BackupPath) {
            $b = Get-Content $BackupPath | Where-Object { $_ -match '^ProviderCLSID=' }
            if ($b) { $target = $b.Substring(14).Trim() }
        }
        Write-Step "deactivate $ca"
        Set-ItemProperty -Path $key -Name 'ProviderCLSID' -Value $target
        Write-Ok ("ProviderCLSID = " + $target)

        if (Test-Path $BackupPath) {
            $provDir = Join-Path (Join-Path $ResponderRoot $ca) 'Provider'
            if (-not (Test-Path $provDir)) { New-Item -ItemType Directory -Force -Path $provDir | Out-Null }
            foreach ($line in (Get-Content $BackupPath | Where-Object { $_ -match '^Provider\\' })) {
                $kv = $line.Substring(9)
                $k, $v = $kv.Split('=', 2)
                Set-ItemProperty -Path $provDir -Name $k -Value $v
                Write-Ok ("Provider\$k = $v")
            }
        }
        Stop-OcspStack
        Start-OcspStack
        Write-Host '=== deactivated ===' -ForegroundColor Green
    }

    'uninstall' {
        if (-not (Test-Admin)) { throw 'uninstall requires an elevated (administrator) PowerShell.' }
        Write-Step 'uninstall'
        Stop-OcspStack

        foreach ($ca in (Get-ResponderCAs)) {
            if ((Get-ProviderClsid $ca) -eq $ProviderCLSID) {
                Set-ItemProperty -Path (Join-Path (Join-Path $ResponderRoot $ca) 'ProviderCLSID') -Name 'ProviderCLSID' -Value $BuiltinCLSID
                Write-Ok ("$ca -> built-in CRL provider")
            }
        }

        if (Test-Path $DllPath) {
            & regsvr32.exe /s /u $DllPath
            Write-Ok ("unregistered (exit " + $LASTEXITCODE + ")")
        }

        Get-ScheduledTask -TaskName 'OcspDbProvider-Sync*' -ErrorAction SilentlyContinue | ForEach-Object {
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
            Write-Ok ("task removed: " + $_.TaskName)
        }
        Remove-Item 'HKLM:\SOFTWARE\OcspDbProvider' -Recurse -Force -ErrorAction SilentlyContinue

        Start-OcspStack
        if ($RemoveFiles) {
            Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok ("removed " + $InstallDir)
        } else {
            Write-Ok ("files kept in $InstallDir (use -RemoveFiles to delete)")
        }
        Write-Host '=== uninstalled ===' -ForegroundColor Green
    }

    'status' {
        $cas = Get-ResponderCAs
        Write-Step 'responder'
        if ($cas.Count -eq 0) { Write-Warn2 'no responder config found' }
        foreach ($ca in $cas) {
            $p = Get-ProviderClsid $ca
            $tag = if ($p -eq $ProviderCLSID) { 'CA-database provider' } elseif ($p -eq $BuiltinCLSID) { 'built-in CRL provider' } else { 'custom' }
            Write-Ok ("{0,-32} ProviderCLSID={1} ({2})" -f $ca, $p, $tag)
        }

        Write-Step 'service'
        $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
        Write-Ok $(if ($svc) { $ServiceName + ' = ' + $svc.Status } else { 'OCSPSvc not installed on this host' })

        Write-Step 'install'
        Write-Ok $(if (Test-Path $DllPath) { $DllPath + '  ' + (Get-Item $DllPath).Length + ' B' } else { 'DLL not installed' })
        Write-Ok $(if (Test-Path $IniPath) { $IniPath } else { 'provider.ini not present (defaults apply)' })

        Write-Step 'snapshots'
        if (Test-Path $DataDir) {
            Get-ChildItem $DataDir -Filter '*.dat' -ErrorAction SilentlyContinue | ForEach-Object {
                $rows = (Get-Content $_.FullName | Where-Object { $_ -and $_[0] -ne '#' }).Count
                Write-Ok ("{0,-40} rows={1,-6} mtime={2}" -f $_.Name, $rows, $_.LastWriteTime)
            }
        } else { Write-Warn2 'no data directory' }

        Write-Step 'scheduled task'
        $tasks = Get-ScheduledTask -TaskName 'OcspDbProvider-Sync*' -ErrorAction SilentlyContinue
        if ($tasks) { $tasks | ForEach-Object { Write-Ok ($_.TaskName + ' state=' + $_.State) } } else { Write-Warn2 'none' }

        if (Test-Path (Join-Path $InstallDir 'provider-native.log')) {
            Write-Step 'provider-native.log (tail)'
            Get-Content (Join-Path $InstallDir 'provider-native.log') -Tail 8 | ForEach-Object { Write-Host ('    ' + $_) }
        }
    }

    'sync' {
        $ca = Resolve-CA
        if ([string]::IsNullOrEmpty($ca)) { throw 'no CA responder config found; pass -CAConfig' }
        Invoke-Sync (Get-CaConfigString $ca)
    }

    'selftest' {
        $uit = Join-Path $InstallDir 'uitest.exe'
        if (-not (Test-Path $uit)) { throw "uitest.exe not found in $InstallDir (run -Mode install)" }
        $ca = Resolve-CA
        # The responder hands over the registry key name (bare CA name), so test with that
        if ([string]::IsNullOrEmpty($ca)) { & $uit info } else { & $uit info -ca $ca }
        if ($LASTEXITCODE -ne 0) { throw "selftest failed (exit $LASTEXITCODE)" }
    }
}
