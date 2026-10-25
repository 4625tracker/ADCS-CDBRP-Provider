# ADCS CDBRP Provider 2.0.0

A native COM revocation provider for **AD CS Online Responder** that answers OCSP from a
snapshot of the **CA certificate database** instead of a CRL. Revocation becomes visible
about one minute after it is recorded, with no CRL publication cycle in the loop.

<sub>**中文摘要**：给 AD CS 联机响应程序用的原生吊销提供程序，数据源是 CA 证书数据库快照而不是
CRL，吊销后约 1 分钟即可在 OCSP 中体现。本版本提供自解包 EXE 安装程序，支持 x64/x86、中英双语、
多 CA。</sub>

## Downloads

| File | Description |
|---|---|
| `ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe` | Installer for 64-bit Windows (most common) |
| `ADCS-CDBRP-Provider-Setup-2.0.0-x86.exe` | Installer for 32-bit Windows |
| `SHA256SUMS.txt` | Checksums for the files above |

The installers embed the provider DLL, the self-test harness and the install/sync scripts;
nothing else needs to be downloaded. They are unsigned, so SmartScreen may warn — verify the
SHA-256 before running.

## Install

```powershell
# right-click -> Run as administrator, or:
.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe
```

The setup extracts its payload to a temporary directory, then runs the same
`install.ps1` that ships in the repository. It installs into
`%ProgramData%\OcspDbProvider`, registers the COM class, writes `provider.ini`, creates the
first snapshot and registers the every-minute refresh task. **It does not switch the
responder yet** — that is a separate, reversible step:

```powershell
.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe -Mode activate
```

Other modes: `deactivate` (back to the built-in CRL provider), `uninstall`,
`status`, `sync`, `selftest`. Add `-CAConfig "SRV1\CORP-CA"` to be explicit about the CA,
`-InstallDir <dir>` to relocate, `-RemoveFiles` with `uninstall` to delete the files too.

Non-elevated inspection of the payload is possible:

```powershell
.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe --list
.\ADCS-CDBRP-Provider-Setup-2.0.0-x64.exe --extract-only C:\temp\payload
```

## Verify

```powershell
# provider contract, no MMC required
& "$env:ProgramData\OcspDbProvider\uitest.exe" info -ca 'SRV1\CORP-CA'

# end to end
openssl ocsp -issuer ca.cer -serial 0x<serial> -url http://<responder>:<port>/ocsp -CAfile ca.cer -no_nonce
# Response verify OK
```

## Requirements

- Windows 7 / Server 2008 R2 or later, x64 or x86
- The AD CS Online Responder role on the target host
- Local administrator rights to install and to switch the provider
- CA database readable by the SYSTEM task (`CA_ACCESS_READ`, 0x100)
- PowerShell 5.1+ (used by the sync task; the provider itself has no PowerShell dependency)

## Highlights

- **CA database as the data source** — no CRL dependency, revocation reflects the database
- **Multi-CA** — independent snapshot and status mapping per CA (`[default]` / `[ca:<id>]`)
- **Bilingual UI** — English and Simplified Chinese, following the system UI language
- **Portable install** — `OCSPDBPROVIDER_DIR` → registry → `%ProgramData%\OcspDbProvider`
- **x64 and x86 builds**; ARM64 build path supported by the scripts (toolchain permitting)
- **Self-contained setup** — embeds DLL, `uitest.exe`, scripts and license; statically
  linked, so no VC++ redistributable is required at runtime
- **No Microsoft binaries are redistributed** — only this project's own code

## Changes since 1.x

- install directory, CA name and host names are no longer hard-coded
- per-CA configuration sections; legacy flat `provider.ini` files still work
- configuration dialog localized (English + Simplified Chinese) with two explicit resources
- thread safety for the MTA apartment the responder uses
- `NormalizeSerial` fixed: digits were mapped to control characters and leading zeros were
  never stripped; lookups only happened to match because both sides were corrupted the same
  way
- the scheduled sync task qualifies a bare CA name with the host name, which certutil requires
- the earlier .NET prototype is kept under `src/legacy/managed` for reference only

## Known limitations

- The setup executables are **not code-signed** (no certificate available). Verify SHA-256.
- ARM64 setups are not published: the ARM64 C++ toolchain is not available in the build
  environment used for this release. The scripts support `-Arch arm64`.
- `nextUpdate` / `nextPublish` are fixed values (30 / 120 minutes), not derived from the CA's
  CRL schedule.
- The provider has no CRL fallback: a missing snapshot makes every serial answer with
  `unknownstatus`.

## Documentation

- [Architecture](https://github.com/4625tracker/ADCS-CDBRP-Provider/blob/main/docs/ARCHITECTURE.md)
- [Deployment](https://github.com/4625tracker/ADCS-CDBRP-Provider/blob/main/docs/DEPLOYMENT.md)
- [Compatibility](https://github.com/4625tracker/ADCS-CDBRP-Provider/blob/main/docs/COMPATIBILITY.md)
- [Reverse engineering notes](https://github.com/4625tracker/ADCS-CDBRP-Provider/blob/main/docs/REVERSE-ENGINEERING.md)

## License

[MIT](https://github.com/4625tracker/ADCS-CDBRP-Provider/blob/main/LICENSE)
