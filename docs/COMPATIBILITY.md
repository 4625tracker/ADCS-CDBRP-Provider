# Compatibility

> **中文摘要**：支持范围、架构与工具链要求、从 1.x 迁移、与内置 CRL 提供程序的行为差异、以及
> 已知限制。核心目标：同一份源码能在 x64/x86/ARM64、Windows 7 及以上、任意安装路径与任意 CA
> 名上工作，不依赖个人环境的写死值。

## 1. What "compatible" means here

| Dimension | Before (1.x) | Now (2.x) |
|---|---|---|
| Install path | hard-coded `D:\NasPlayData\ocsp` | env var → registry → `%ProgramData%\OcspDbProvider` |
| CA name | hard-coded `NAS-Monitor-CA` | configured per CA (`[ca:<ca-id>]`), auto-detected on install |
| CA count | one global snapshot | one snapshot + status mapping per CA |
| UI language | Chinese only | English + Simplified Chinese, follows the system, overridable |
| Architecture | x64 only | x64 / x86 / ARM64 |
| Windows baseline | untested below the build host | explicit `_WIN32_WINNT = 0x0601` (Windows 7 / Server 2008 R2) |
| Toolchain | one VS 18 path | any VS 2019/2022/Build Tools found by `vswhere` |
| Configuration | flat file only | flat file (legacy) or `[default]` + `[ca:...]` sections |
| Verification | manual MMC + openssl | `scripts/test.ps1` (14 assertions, no admin) |

## 2. Supported matrix

| OS | x64 | x86 | ARM64 |
|---|---|---|---|
| Windows Server 2008 R2 | ✓ | ✓ | n/a |
| Windows Server 2012 / 2012 R2 | ✓ | ✓ | n/a |
| Windows Server 2016 / 2019 / 2022 / 2025 | ✓ | ✓ | ✓ (with ARM64 toolchain) |
| Windows 7 / 8.1 / 10 / 11 | ✓ | ✓ | ✓ (with ARM64 toolchain) |

Notes:

- The **build host** and the **target host** are independent: the DLL only links
  `kernel32/ole32/oleaut32/advapi32/user32/comdlg32/gdi32` and the C runtime statically
  (`/MT` is not used; the DLL links the import libraries only, so no VC++ redistributable
  is required).
- **ARM64 requires** the optional component *MSVC v14x - C++ ARM64 build tools* in the
  Visual Studio Installer. Without it `scripts/build.ps1 -Arch arm64` fails with an explicit
  message instead of a linker error. This repository ships no ARM64 build artifacts, so an
  ARM64 build should be validated on real hardware.
- `x86` requires the *x86 build tools* component; on a 64-bit host the script uses
  `vcvarsamd64_x86.bat`.

## 3. Runtime requirements

| Item | Requirement |
|---|---|
| PowerShell | 5.1+ (scripts only; not needed at OCSP runtime) |
| .NET | not used by the provider |
| VC++ redistributable | not required |
| Registry | `HKCR\CLSID\{...}` (registration) and `HKLM\SOFTWARE\OcspDbProvider` (install dir) |
| Service identity | `NETWORK SERVICE` needs read/execute on the install directory |
| CA access | `CA_ACCESS_READ` (0x100) for whoever runs `certutil -view` (the SYSTEM task) |

## 4. Migration from 1.x

`scripts/install.ps1` looks for the legacy directory (default `D:\NasPlayData\ocsp`, override
with `-MigrationSource`) and, if `provider.ini` / `revdb.dat` exist and the new install dir
has no configuration yet, it:

1. copies `revdb.dat` to `%ProgramData%\OcspDbProvider\data\revdb.dat`;
2. carries over `checkseconds` / `validstatus` / `revokedstatus` / `unknownstatus`;
3. writes a new `provider.ini` whose `[default]` snapshot points at the copied file.

Legacy flat configuration files (no sections) keep working unchanged: flat keys are treated
as `[default]`, which applies to every CA. That is the 1.x single-CA behaviour.

## 5. Behavioural differences vs the built-in CRL provider

| Aspect | Built-in (CRL) | This provider |
|---|---|---|
| Data source | published CRL | CA database snapshot |
| Revocation latency | CRL publication interval | sync interval (default 1 min) |
| Unknown serial | reported as `good` | `unknownstatus` (default `0` = `good`, same as built-in) |
| `thisUpdate` / `nextUpdate` | from the CRL | `now` / `now + 30 min` (fixed, not configurable) |
| Signature | responder key | responder key (unchanged) |
| Config storage | `Responder\<CA>\Provider` | the same key, plus `provider.ini` |

The OCSP response itself is still signed by the responder; the provider only supplies
per-serial status. Nonces are handled by `ocspsvc.exe`.

## 6. Configuration reference

| Key | Default | Meaning |
|---|---|---|
| `snapshot` | `<install>\data\<safe-ca>.dat` | snapshot file |
| `checkseconds` | `2` | snapshot mtime check interval; `0` = every query |
| `validstatus` | `0` | `dwStatus` for good |
| `revokedstatus` | `1` | `dwStatus` for revoked |
| `unknownstatus` | `0` | `dwStatus` for serials absent from the snapshot |

Sections: `[default]` (or a flat file) applies to all CAs; `[ca:<ca-id>]` overrides one CA.
Every key is optional.

Environment overrides (mainly for testing and relocated installs):

| Variable | Effect |
|---|---|
| `OCSPDBPROVIDER_DIR` | install/config/snapshot root |
| `OCSPDBPROVIDER_LANG` | `zh` / `en` |
| `OCSPDBPROVIDER_CAPTURE` | `1` = dialog self-test mode |
| `OCSPDBPROVIDER_CAPTURE_DIR` | dump directory for the dialog capture |
| `OCSPDBPROVIDER_CA` | default CA id for `uitest.exe` |

## 7. Known limitations

- The snapshot is a text file; very large CAs (hundreds of thousands of serials) mean a
  larger file and a slightly slower reload. Parsing is a single pass into a hash map.
- `certutil -view` output is parsed by shape, not by label, so it is locale-tolerant; a
  future change to certutil's output layout would need a parser update.
- Only revocation *status* is derived from the database. `nextUpdate` / `nextPublish` are
  fixed values (30 / 120 minutes), not scheduled from the CA's CRL configuration.
- The scheduled task uses `powershell.exe`; on hosts where PowerShell script execution is
  restricted by policy, adjust the task to call `sync.ps1` through an approved launcher.
- The provider does not implement a CRL fallback: if the snapshot is missing, every serial
  is answered with `unknownstatus`.
