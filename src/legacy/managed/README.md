# Legacy managed (.NET) prototype — unsupported

These files are kept for reference only. They are the earlier attempt at writing the
revocation provider in C# instead of native C++.

**They are not built, not tested and not supported.** `scripts/build.ps1` ignores this
directory; `scripts/install.ps1` installs the native provider in `src/native/`.

## Why it was abandoned

A managed in-proc COM server inside the Online Responder hits three problems that the
native implementation does not:

1. the managed RCW behaves unpredictably in the responder's MTA apartment, and failures
   surfaced as HTTP `500` with no useful error;
2. `GetConfigInformation` must return a VARIANT-carried `SAFEARRAY`, not a byte buffer —
   doing this from C# through `CERTTRANSBLOB` is fragile, and getting it wrong corrupts the
   responder's heap (`0xc0000374`);
3. `RevStatusInfo` must be exactly 40 bytes; a missing `Pack = 1` shifts every timestamp and
   produces `Bad time value` in every OCSP response.

The native provider in `src/native/` addresses all three directly. See
[../../docs/REVERSE-ENGINEERING.md](../../docs/REVERSE-ENGINEERING.md) for the contract and
the analysis behind it.

## What is still useful here

- `OcspDbProvider.cs` — the `certutil -view` output parser used as the basis for
  `scripts/sync.ps1`, plus the original status-mapping experiments.
- `RevDbSyncMain.cs` — the original `RevDbSync.exe` entry point.

All hard-coded paths point at `C:\ProgramData\OcspDbProvider` and the CA name is the
placeholder `CA-NAME`; adjust before building if you really want to try it:

```powershell
csc /target:library /out:OcspDbProvider.dll OcspDbProvider.cs
csc /target:exe /r:OcspDbProvider.dll /out:RevDbSync.exe RevDbSyncMain.cs
```
