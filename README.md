# OCSP CA-Database Revocation Provider (CDBRP)

A native COM revocation provider for **AD CS Online Responder** that answers OCSP from a
snapshot of the **CA certificate database** instead of a CRL.

Once a certificate is revoked in the CA database, the responder can report it within about
one minute — no CRL publication cycle, no CRL distribution point in the loop.

<sub>**中文摘要**：给 AD CS 联机响应程序（OCSPSvc）用的原生 COM 吊销提供程序，吊销数据取自 CA
证书数据库快照而不是 CRL，吊销后约 1 分钟即可在 OCSP 中体现。支持多 CA、中英双语、x64/x86/ARM64。
仓库不含任何微软二进制文件。</sub>

---

## Why

The built-in provider (`ocsprevp.dll`) answers from the CRL. That means an OCSP client can
be told `good` for a certificate that was revoked minutes ago and whose new CRL has not been
published yet. This provider reads the CA database directly (via `certutil -view`), so
revocation is visible as soon as the database is written.

## How it works

```
CA certificate database (CertLog\*.edb)
        |  certutil -view            <- scheduled task, every minute, as SYSTEM
        v
<install>\data\<ca-id>.dat           <- snapshot: serial \t disposition \t revokedWhen \t reason \t notAfter
        |  in-memory cache, reloaded when the file mtime changes
        v
OcspDbProvider.dll  (native COM, CLSID {7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9})
        |  IOCSPRevInfoProvider::VerifySerialNumber
        v
ocspsvc.exe -> IIS (/ocsp) -> clients
```

The interface contract was recovered by reverse engineering `ocsprevp.dll` and `ocspsvc.exe`;
the interesting parts (including two traps that corrupt the heap or misplace every timestamp)
are documented in [docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md).

## Features

- **Native C++ in-proc COM server** — no CLR inside the responder process.
- **CA database as the data source** — revocation latency is bounded by the sync interval.
- **Per-CA configuration and snapshots** — several responders/CA configs can share one DLL.
- **Bilingual configuration UI** — English and Simplified Chinese, following the system UI
  language, overridable with `OCSPDBPROVIDER_LANG`.
- **Portable install location** — `%ProgramData%\OcspDbProvider` by default, fully overridable.
- **x64 / x86 / ARM64** build (ARM64 requires the VC ARM64 toolchain component).
- **Windows 7 / Server 2008 R2 and later**.
- **Scripts** for build, install, activate, deactivate, uninstall, snapshot sync and a
  self-check that runs without administrator rights.
- **No Microsoft binaries in this repository.** Only this project's own code.

## Releasing

Two ways, both produce the same artifacts:

- **GitHub Actions (no local tooling):** push a tag like `v2.0.0` — `.github/workflows/release.yml`
  builds the x64 and x86 setups on a Windows runner, runs the self check, writes
  `SHA256SUMS.txt` and publishes the release with `docs/RELEASE-NOTES-<version>.md` as the body.
- **Locally:** `pwsh -File scripts/release.ps1` builds both setups into `dist/`, writes the
  checksums and prints the exact `gh release create` command (or the web-UI steps) when `gh`
  is not available.

## Quick start

### From a release (no build tools needed)

Download `OCSP-CDBRP-Provider-Setup-<version>-<arch>.exe` from
[Releases](https://github.com/4625tracker/OCSP-CDBRP-Provider/releases), verify its SHA-256
against `SHA256SUMS.txt`, then run it **as administrator**:

```powershell
.\OCSP-CDBRP-Provider-Setup-2.0.0-x64.exe                 # install (does not switch the responder)
.\OCSP-CDBRP-Provider-Setup-2.0.0-x64.exe -Mode activate  # switch the responder to this provider
.\OCSP-CDBRP-Provider-Setup-2.0.0-x64.exe -Mode status    # read-only overview, no elevation
```

The setup embeds the DLL, `uitest.exe`, the scripts and the license; it extracts to a temp
directory and runs the same `install.ps1` described below, so there is only one install
implementation. `--help`, `--list` and `--extract-only <dir>` work without elevation.
The setup executables are unsigned — check the checksum before running.

### From source

Prerequisites: Windows with **Visual Studio 2019/2022** (or Build Tools) including the
*Desktop development with C++* workload, and PowerShell 5.1+.

```powershell
# build + run the self check (no admin needed, does not touch the registry)
pwsh -File scripts/test.ps1

# install: copy, regsvr32, provider.ini, first snapshot, scheduled task (elevated)
pwsh -File scripts/install.ps1 -Mode install -CAConfig 'SRV1\CORP-CA'

# switch the responder to this provider (elevated)
pwsh -File scripts/install.ps1 -Mode activate

# roll back to the built-in CRL provider
pwsh -File scripts/install.ps1 -Mode deactivate

# state overview
pwsh -File scripts/install.ps1 -Mode status
```

Verify with OpenSSL:

```bash
openssl ocsp -issuer ca.cer -serial 0x6200000003CC4141256F50414D000000000003 \
  -url http://<responder>:<port>/ocsp -CAfile ca.cer -no_nonce
# Response verify OK
```

## Configuration

`%ProgramData%\OcspDbProvider\provider.ini` (UTF-8, `key=value`, sections optional):

```ini
[default]
checkseconds=2      ; snapshot cache lifetime; 0 = re-check on every query
validstatus=0       ; dwStatus for "good"
revokedstatus=1     ; dwStatus for "revoked"
unknownstatus=0     ; dwStatus for serials not present in the snapshot
                    ; (0 matches what the built-in CRL provider reports for unknown serials)

[ca:SRV1\CORP-CA]   ; optional per-CA overrides
snapshot=C:\ProgramData\OcspDbProvider\data\CORP-CA.dat
unknownstatus=2     ; answer RFC 6960 "unknown" instead of "good"
```

A flat file with no sections is also accepted (legacy 1.x layout) and applies to every CA.

### Multi-CA configuration (GUI)

`OcspConfig.exe` ships next to the provider and edits every CA in one place:

```powershell
& "$env:ProgramData\OcspDbProvider\OcspConfig.exe"
```

It lists the CAs found in the responder configuration and in `provider.ini`, lets you edit
the snapshot path, cache seconds and the three status codes per CA, and shows the live state
of that CA's snapshot (resolved path, whether the file exists, its size, parsable rows and
modification time). Saving only touches that CA's `[ca:<id>]` section; removing one only
drops that section.

The same operations are scriptable:

```powershell
OcspConfig.exe --dump
OcspConfig.exe --set CORP-A --snapshot C:\data\CORP-A.dat --unknown 2
OcspConfig.exe --remove CORP-B
```

| Environment variable | Purpose |
|---|---|
| `OCSPDBPROVIDER_DIR` | Install directory (overrides the registry/ProgramData default) |
| `OCSPDBPROVIDER_LANG` | `zh` / `en` — force the UI language |
| `OCSPDBPROVIDER_CAPTURE` | `1` — self-test mode: dump the dialog and auto-confirm |
| `OCSPDBPROVIDER_CAPTURE_DIR` | Where the dialog dump is written |
| `OCSPDBPROVIDER_CA` | Default CA id for `uitest.exe` |

Resolution order for the install directory: `OCSPDBPROVIDER_DIR` → `HKLM\SOFTWARE\OcspDbProvider\InstallDir`
→ `%ProgramData%\OcspDbProvider`.

## Repository layout

```
src/native/            provider DLL, config model (shared), self-test harness, OcspConfig tool
src/setup/             setup EXE: embedded payload, self-elevation, runs install.ps1
src/legacy/managed/    earlier managed (.NET) prototype, unsupported
scripts/               build, build-installer, install, uninstall, sync, test, release
docs/                  architecture, deployment, compatibility, reverse-engineering
test/                  helpers to build a throw-away test PKI
dist/                  release artifacts (generated, not committed)
```

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Interfaces, structures, data flow, multi-CA model |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Install, activate, verify, roll back, troubleshoot |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | OS/arch/toolchain matrix, migration from 1.x |
| [docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md) | Recovered COM contract and the traps |

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every request returns `unauthorized` | Provider not registered / `ProviderCLSID` not switched / responder cannot read the CA |
| Every request returns `500` with a heap corruption event | `GetConfigInformation` returned a byte buffer instead of a VARIANT-carried `SAFEARRAY` |
| `This Update: Bad time value` in the OCSP response | `RevStatusInfo` not packed to 1 byte (48 instead of 40 bytes) |
| All serials answered as `good` | Snapshot empty or unreadable; check `provider-native.log` and the task state |
| MMC snap-in crashes when the provider is selected | `GetStatus` must return a `VT_ARRAY|VT_BSTR`, not a single `BSTR` |
| `0x800706BA` when running `certutil` | CA config string needs the host prefix (`HOST\CA-NAME`) |

## License

[MIT](LICENSE). No Microsoft binaries are redistributed; `docs/REVERSE-ENGINEERING.md`
contains observations about interfaces implemented by Microsoft software, made for
interoperability.

---

# 中文说明

## 这是什么

给 **AD CS 联机响应程序**（`ocspsvc.exe`）用的原生 COM 吊销提供程序：OCSP 的吊销状态来自
**CA 证书数据库快照**，不读 CRL。吊销后约 1 分钟即可在 OCSP 中看到，不用等 CRL 发布。

内置提供程序（`ocsprevp.dll`）读的是 CRL，因此会出现"证书刚被吊销、新 CRL 还没发布，OCSP 仍报 good"
的窗口。本提供程序直接读 CA 数据库（`certutil -view`），数据库一写入就能反映。

## 特性

- 原生 C++ 进程内 COM，响应程序进程里没有 CLR；
- 多 CA：每个 CA 独立快照、独立状态码映射；
- 配置界面中英双语（跟随系统 UI 语言，可用 `OCSPDBPROVIDER_LANG` 强制）；
- 安装目录默认 `%ProgramData%\OcspDbProvider`，可用环境变量/注册表覆盖；
- x64 / x86 / ARM64 构建（ARM64 需要安装 VC 的 ARM64 工具链）；
- 最低 Windows 7 / Server 2008 R2；
- 提供构建、安装、激活、回滚、卸载、快照同步与自检脚本；自检不需要管理员权限。

## 三步上手

```powershell
pwsh -File scripts/test.ps1                                    # 构建 + 自检（无需管理员）
pwsh -File scripts/install.ps1 -Mode install -CAConfig 'SRV1\CORP-CA'   # 安装（需管理员）
pwsh -File scripts/install.ps1 -Mode activate                  # 切换响应程序到本提供程序
```

回滚：`scripts/install.ps1 -Mode deactivate`（恢复内置 CRL 提供程序）。

## 配置

`%ProgramData%\OcspDbProvider\provider.ini`，UTF-8，`key=value`：

```ini
[default]
checkseconds=2
validstatus=0
revokedstatus=1
unknownstatus=0

[ca:SRV1\CORP-CA]
snapshot=C:\ProgramData\OcspDbProvider\data\CORP-CA.dat
unknownstatus=2
```

老的平铺格式（1.x）仍可直接使用，等价于 `[default]`。

## 已知坑（都是逆向出来的）

1. `GetConfigInformation` 的返回值不是字节块，而是 `CERTTRANSBLOB` 承载的 VARIANT
   （`cb` 放 VARTYPE、`pb` 是 `SAFEARRAY*`）；按字节缓冲返回会让 `ocspsvc.exe` 堆损坏崩溃。
2. `RevStatusInfo` 必须 1 字节紧密排列（40 字节），否则时间字段全错位，OCSP 里表现为
   `Bad time value`。
3. `IOCSPRevInfoProviderManager::GetStatus` 的状态值必须是 `VT_ARRAY|VT_BSTR`，给单个 `BSTR`
   会让托管 snapin 抛 `InvalidCastException` 并带崩 `mmc.exe`。
4. 联机响应程序传进来的序列号是**字节反序**的，匹配前要按字节反转。
5. CA 配置串必须带主机前缀（`机器名\CA名`），裸 CA 名会报 `0x800706BA`。

详见 [docs/REVERSE-ENGINEERING.md](docs/REVERSE-ENGINEERING.md)。

## 许可

[MIT](LICENSE)。仓库不包含任何微软二进制文件。
