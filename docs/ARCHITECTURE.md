# Architecture

> **中文摘要**：本文说明提供程序的 COM 契约、数据结构、数据来源、缓存与并发模型，以及多 CA
> 的配置与快照命名规则。想了解这些契约是怎么逆向出来的，见
> [REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md)。

## 1. Position in the responder

```
client --HTTP--> IIS (OCSP ISAPI) --> ocspsvc.exe --COM(in-proc)--> OcspDbProvider.dll
                                                                        |
                                                              snapshot file per CA
                                                                        ^
                                              scheduled task (SYSTEM, every minute)
                                                                        |
                                                        certutil -view  <- CA database
```

`ocspsvc.exe` co-creates the provider with `CLSCTX_INPROC_SERVER` and `IID_IOCSPRevInfoProvider`,
in an **MTA** apartment (`CoInitializeEx(NULL, COINIT_MULTITHREADED)`), so the provider is
called concurrently and must be thread safe.

## 2. COM contract

```c
struct CERTTRANSBLOB { ULONG cb; PBYTE pb; };

IOCSPRevInfoProvider {93F568FF-B8C7-483B-8DEF-5E6EEF8B7650}
  Initialize(BSTR caId, CERTTRANSBLOB *caCert, CERTTRANSBLOB *config)
  VerifySerialNumber(CERTTRANSBLOB *serial, RevStatusInfo *status)
  GetConfigInformation(CERTTRANSBLOB *config)
  GetProviderManager(IUnknown **mgr)
  // + 4 IDispatch slots (dual interface, must exist for the vtable to line up)

IOCSPRevInfoProviderManager {F85C5127-F108-497D-8FCC-B2A709047C98}
  GetProviderInformation(BSTR *name, BSTR *desc)
  Configure(HWND, BSTR caId, blob *caCert, blob *in, BOOL *modified, blob *out)
  View(HWND, BSTR caId, blob *caCert, blob *in)
  GetStatus(BSTR caId, blob *caCert, blob *in, VARIANT *status, HRESULT *hr)
  Initialize(BSTR caId, blob *caCert, blob *out)
```

`RevStatusInfo` is 40 bytes, packed:

| offset | field |
|---|---|
| 0 | `DWORD dwStatus` (0 = good, 1 = revoked, 2 = unknown) |
| 4 | `FILETIME ftThisUpdate` |
| 12 | `FILETIME ftNextUpdate` |
| 20 | `FILETIME ftNextPublish` |
| 28 | `FILETIME ftRevocationDate` |
| 36 | `DWORD dwRevocationReason` |

The `config` parameters are **not byte buffers**. `CERTTRANSBLOB::cb` carries a VARTYPE and
`pb` carries a `SAFEARRAY*` (`0x200C` = `VT_ARRAY|VT_VARIANT`). Returning a byte buffer makes
the responder free it as a variant array and corrupts the heap. See
[REVERSE-ENGINEERING.md §6](REVERSE-ENGINEERING.md).

## 3. Data source and snapshot format

One snapshot per CA, produced by `scripts/sync.ps1`:

```
# comment lines start with '#'
<serial> <TAB> <disposition> <TAB> <revokedWhen FILETIME> <TAB> <reason> <TAB> <notAfter FILETIME>
```

- `serial` is the hex serial as printed by `certutil`; the provider normalizes it
  (uppercase, no leading zeros).
- `disposition` follows the CA database values: `21` = revoked, `20/15/14` = valid,
  anything else is reported as `unknown`.
- the two times are Windows `FILETIME` values (`0` = not set).

The file is written atomically (`.tmp` + replace) so a concurrent read never sees a partial file.

## 4. Caching and concurrency

- Each CA has its own `RevDb` object holding the parsed map, the file stamp and the last
  load time.
- On every query the provider checks the snapshot file's last write time at most once per
  `checkseconds` (default 2, `0` = every query). A changed stamp triggers a reload.
- All map access is guarded by a single critical section; lookups are plain in-memory map
  operations, so contention is negligible.
- The dialog's *Reload snapshot now* button forces an immediate reload for that CA.

## 5. Multi-CA model

The responder passes the CA id to `Initialize`. Everything is keyed by that id:

| thing | rule |
|---|---|
| default snapshot | `<install>\data\<safe-ca-id>.dat`, where `safe-ca-id` keeps `[A-Za-z0-9._-]` and maps everything else to `_` (so `SRV1\CORP-CA` → `SRV1_CORP-CA`) |
| config section | `[ca:<ca-id>]` overrides `[default]` |
| status mapping | per CA, inheriting from `[default]` |
| cache | per CA |

Because the exact spelling of the CA id is an implementation detail of the responder,
`scripts/install.ps1` writes a section for both `CORP-CA` and `SRV1\CORP-CA` pointing at the
same file. If you add a second CA later, the configuration dialog writes its own section.

## 6. Registration

`DllRegisterServer` writes:

```
HKCR\CLSID\{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}
    (default) = localized provider name
    InprocServer32\(default) = <full path to DLL>
    InprocServer32\ThreadingModel = Both
HKCR\OcspDb.RevInfoProvider.1\CLSID = {7B0C4B1E-...}
HKLM\SOFTWARE\OcspDbProvider\InstallDir = <install dir>
```

The last value is how the provider finds its configuration and snapshot directory after a
`regsvr32` on a different machine layout.

## 7. Self-test harness

`uitest.exe` exercises the same interfaces without MMC:

```powershell
uitest.exe info                        # GetProviderInformation + GetStatus
uitest.exe verify <serial-hex>         # VerifySerialNumber
uitest.exe config | view               # the configuration dialog
uitest.exe rescheck                    # dialog/version resources only (headless friendly)
uitest.exe selftest                    # info + verify + config, dialog auto-closed

# options
-dll <path>    load the DLL directly (no registration, no admin needed)
-ca <ca-id>    CA id passed to Initialize
-lang zh|en    force the UI language
# note: only `selftest` and `config` open a window; `rescheck` never does
```

`scripts/test.ps1` builds the fixtures, runs this harness and asserts on the results.
