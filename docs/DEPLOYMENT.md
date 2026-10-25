# Deployment

> **中文摘要**：安装、激活、验证、回滚与排错。默认安装目录 `%ProgramData%\OcspDbProvider`，
> 所有脚本幂等，激活与回滚都可逆（会写 `rollback.txt`）。

## 1. Prerequisites

| Item | Requirement |
|---|---|
| Host | Windows Server with the **AD CS Online Responder** role (or Windows 10/11 + that role) |
| CA | Enterprise/Standalone CA database reachable; the responder identity needs `CA_ACCESS_READ` (0x100) |
| Build host | Visual Studio 2019/2022 or Build Tools with *Desktop development with C++* |
| Runtime | PowerShell 5.1+ (for the scripts only; the provider itself has no PowerShell dependency) |
| Rights | Local administrator for install/activate; the sync task runs as `SYSTEM` |

The provider is a plain in-proc COM DLL: no .NET runtime, no VC++ redistributable
(it links only `ole32/oleaut32/advapi32/user32/comdlg32/gdi32`, all present on Windows).

## 2. Install

```powershell
pwsh -File scripts/install.ps1 -Mode install -CAConfig 'SRV1\CORP-CA'
```

What it does:

1. builds `out\<arch>\OcspDbProvider.dll` (unless already present, `-Rebuild` forces it);
2. stops `OCSPSvc` and the OCSP app pool so the DLL file can be replaced;
3. copies the DLL plus `uitest.exe` and `sync.ps1` into `%ProgramData%\OcspDbProvider`;
4. runs `regsvr32` and verifies `InprocServer32` points at the installed copy;
5. grants `NETWORK SERVICE` read/execute on the install dir;
6. migrates an existing 1.x configuration from `D:\NasPlayData\ocsp` if present;
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
