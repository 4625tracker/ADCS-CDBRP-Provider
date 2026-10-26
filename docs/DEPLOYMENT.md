# Deployment

> **中文摘要**：安装、激活、验证、回滚与排错。默认安装目录 `%ProgramData%\OcspDbProvider`，
> 所有脚本幂等，激活与回滚都可逆（会写 `rollback.txt`）。

## 1. Prerequisites

| Item | Requirement |
|---|---|
| Host | Windows Server with the **AD CS Online Responder** role (or Windows 10/11 + that role) |
| CA | Enterprise/Standalone CA database reachable; the responder identity needs `CA_ACCESS_READ` (0x100) |
| Build host | Visual Studio 2019/2022 or Build Tools with *Desktop development with C++* — **only when building from source**; the release setup EXE needs nothing |
| Runtime | PowerShell 5.1+ (for the scripts only; the provider itself has no PowerShell dependency) |
| Rights | Local administrator for install/activate; the sync task runs as `SYSTEM` |

The provider is a plain in-proc COM DLL: no .NET runtime, no VC++ redistributable
(it links only `ole32/oleaut32/advapi32/user32/comdlg32/gdi32`, all present on Windows).

## 2. Install

### 2.1 From the setup EXE (recommended)

```powershell
# verify the download first
Get-FileHash .\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe -Algorithm SHA256
# compare with the line for this file in SHA256SUMS.txt

.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe                    # install
.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe -Mode activate     # switch the responder
```

The setup is `asInvoker` and elevates itself with `runas` only for the modes that need it
(`install`, `activate`, `deactivate`, `uninstall`, `sync`). `-Mode status`, `--list` and
`--extract-only <dir>` never prompt for elevation. It extracts its embedded payload
(DLL, `uitest.exe`, `install.ps1`, `sync.ps1`, license) to a temporary directory and runs
the very same `install.ps1` described below, so the install logic exists once.

Useful flags: `-CAConfig "SRV1\CORP-CA"`, `-InstallDir <dir>`, `-RemoveFiles` (uninstall),
`--quiet`, `--keep-temp`, `--help`.

### 2.2 From source

```powershell
pwsh -File scripts/install.ps1 -Mode install -CAConfig 'SRV1\CORP-CA'
```

What it does:

1. builds `out\<arch>\OcspDbProvider.dll` (unless already present, `-Rebuild` forces it);
2. stops `OCSPSvc` and the OCSP app pool so the DLL file can be replaced;
3. copies the DLL plus `uitest.exe` and `sync.ps1` into `%ProgramData%\OcspDbProvider`;
4. runs `regsvr32` and verifies `InprocServer32` points at the installed copy;
5. grants `NETWORK SERVICE` read/execute on the install dir;
6. optionally migrates an existing 1.x configuration when `-MigrationSource <dir>` is given
   (nothing is assumed by default, so no legacy path is baked into the tooling);
7. writes `provider.ini` (never overwrites an existing one);
8. creates the first snapshot and registers the scheduled task `OcspDbProvider-Sync-<ca>`.

The responder is **not** switched yet — install and activation are deliberately separate.

## 3. Activate

```powershell
pwsh -File scripts/install.ps1 -Mode activate
```

- backs up the current `ProviderCLSID` (and the `Provider` subkey) to `rollback.txt`;
- sets `ProviderCLSID` to `{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}`;
- restarts `OCSPSvc` and the app pool.

## 4. Verify

```powershell
# provider sees the snapshot
pwsh -File scripts/install.ps1 -Mode status

# COM contract, no MMC
& "$env:ProgramData\OcspDbProvider\uitest.exe" info -ca 'SRV1\CORP-CA'
```

```bash
openssl ocsp -issuer ca.cer -serial 0x6200000003CC4141256F50414D000000000003 \
  -url http://<responder>:<port>/ocsp -CAfile ca.cer -no_nonce
```

Expected: `Response verify OK`, `Cert Status: revoked`, with the revocation time and reason
matching the CA database. A serial that is not in the database is answered according to
`unknownstatus`.

## 5. Configuration

Edit `%ProgramData%\OcspDbProvider\provider.ini`, or use the provider's property dialog in
the *Online Responder* MMC snap-in, or the same dialog without MMC:

```powershell
& "$env:ProgramData\OcspDbProvider\uitest.exe" config -ca 'SRV1\CORP-CA'
```

For several CAs, use the dedicated editor — it lists every CA (from the responder and from
`provider.ini`), edits one CA at a time and shows that CA's snapshot state:

```powershell
& "$env:ProgramData\OcspDbProvider\OcspConfig.exe"
```

Headless equivalents for scripting:

```powershell
$cfg = "$env:ProgramData\OcspDbProvider\OcspConfig.exe"
& $cfg --dump
& $cfg --set 'SRV1\CORP-CA' --snapshot 'C:\data\CORP-CA.dat' --check 2 --unknown 2
& $cfg --remove 'SRV1\OLD-CA'
```

After editing the file by hand, restart the service:

```powershell
Restart-Service OCSPSvc -Force
Restart-WebAppPool OCSPISAPIAppPool    # order matters: service first
```

## 6. Snapshots

```powershell
# refresh now
pwsh -File scripts/install.ps1 -Mode sync -CAConfig 'SRV1\CORP-CA'

# or directly, e.g. for a different CA
pwsh -File scripts/sync.ps1 -CA 'SRV1\CORP-CA' -Out C:\ProgramData\OcspDbProvider\data\CORP-CA.dat
```

The scheduled task runs every minute as `SYSTEM`; check it with
`Get-ScheduledTask -TaskName 'OcspDbProvider-Sync*'`.

## 7. Roll back

```powershell
pwsh -File scripts/install.ps1 -Mode deactivate    # back to the built-in CRL provider
pwsh -File scripts/uninstall.ps1 -RemoveFiles      # remove completely
```

`deactivate` restores the exact previous `ProviderCLSID` from `rollback.txt` (falls back to
the built-in `{4956d17f-88fd-4198-b287-1e6e65883b19}`).

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| every OCSP request `unauthorized` | `ProviderCLSID` actually switched? DLL registered? event log for `0xD34089B` / `0xD3D089B` |
| `500` + `Application Error 1000` / `0xc0000374` | provider returned a byte buffer where a VARIANT `SAFEARRAY` is expected |
| `This Update: Bad time value` | `RevStatusInfo` packing (must be 40 bytes) |
| every serial answered `good` | snapshot empty / unreadable → `provider-native.log`, task state, `data\*.dat` size |
| sync fails with `0x800706BA` | CA config string needs the host prefix (`HOST\CA-NAME`) |
| sync fails with access denied | grant the CA `Read` permission to the task/service identity; `CA_ACCESS_READ = 0x100` |
| MMC crashes when the provider is selected | `GetStatus` must return `VT_ARRAY|VT_BSTR` |
| app pool `unauthorized` | the `/ocsp` vdir must run on the pool that has `0x300` on `Responder\OCSPSecurity` |

### "A revocation takes much longer than a minute to show up"

Three stages can each add latency, and each has its own check. Fixing the wrong one wastes a
lot of time, so measure before changing anything.

| Stage | What to check | Normal value |
|---|---|---|
| 1. Snapshot refresh | `Get-ScheduledTaskInfo -TaskName OcspDbProvider-Sync-<CA>` → `LastRunTime` advances; the `.dat` mtime advances with it | ~61 s |
| 2. Provider reload | `uitest.exe info -ca <CA>` → `Last snapshot load` keeps up with the file time | ≤ `checkseconds` (default 2 s) |
| 3. **Response caching** | query the same serial twice ~10 s apart while watching `provider-native.log`: a second query with **no** new `VerifySerialNumber` line means the answer came from the responder's cache | ≤ `responseseconds` (default 60 s) |

Stage 3 is the one that surprises people: `nextUpdate` in the answer is what the responder (and
the client) may cache until, so a 30-minute window makes a freshly revoked certificate look
`good` for half an hour **even though the snapshot is perfect**. Measured end to end with the
defaults: **62 seconds**.

Stage 1 failures usually look like a `.dat` file that simply never changes. Two causes have
been seen in the field:

- the task was registered with an empty `<Triggers/>` (older installers did this) — `Get-ScheduledTask` shows `Triggers.Count = 0` and `LastRunTime = 1601-01-01`/`1999-11-30`;
- the action carries a non-ASCII CA name that got mangled in transit, so `certutil` fails with
  `E_INVALIDARG (0x80070057)` on every run — the task result is `0x1` and `sync.log` shows a
  doubled host prefix. Current versions pass no CA name to the task and let `sync.ps1` resolve
  it from the responder registry.

### "OCSP returns 500 every so often, and never when I test it"

A 500 that comes and goes is usually not this provider — it is the responder being restarted
under you. Check for a **restart workaround** left over from the built-in CRL provider:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddHours(-2)} |
  Where-Object { $_.Id -in 17,18 } | Select TimeCreated,Id     # OCSPSvc stopped/started pairs
Get-ScheduledTask | Where-Object { $_.Actions.Arguments -match 'OCSPSvc|Restart-Service' }
```

A task that restarts `OCSPSvc` whenever the CRL changes (a common workaround, because the
built-in provider only re-reads a CRL on startup) fires on **every CRL republication** — so a
CA publishing a CRL every ten minutes causes a restart every ten minutes, and each restart has
a window where requests fail with 500.

The CA-database provider does not need that workaround: it re-reads its snapshot when the file
changes, without a restart. Disable the task (`Disable-ScheduledTask -TaskName <name>`) and the
intermittent 500s stop. Re-enable it if you ever roll back to the built-in provider.

Logs:

- `%ProgramData%\OcspDbProvider\provider-native.log` — DLL load, `Initialize`, first queries
- `%ProgramData%\OcspDbProvider\sync.log` — snapshot regeneration
- Event log → Windows Logs → Application (source `OCSPSvc`)

## 9. Uninstall

```powershell
pwsh -File scripts/uninstall.ps1                # keep files and snapshots
pwsh -File scripts/uninstall.ps1 -RemoveFiles   # delete the install directory too
```

It restores the built-in provider for every responder config that points at this CLSID,
unregisters the COM class, removes the scheduled task and the `HKLM\SOFTWARE\OcspDbProvider` key.
