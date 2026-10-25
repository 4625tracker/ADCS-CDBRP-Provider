<!--
Thanks for the pull request. Keep it to one topic, and say how you verified it:
a command and its output beats a paragraph of description.

The checklist at the bottom is short because those are the things that break deployed
responders. If an item does not apply, say why rather than deleting it.

中文：一个 PR 只做一件事；请附上验证命令和输出。底部清单里的几条都是会打断已部署服务的
东西，不适用就说明原因，别直接删掉。
-->

## What this changes

<!-- One paragraph. What is different after this patch? -->

## Why

<!-- The problem first. Link the issue if there is one (`Fixes #12`). -->

## How it was verified

<!--
Paste the real output, e.g.

    pwsh -File scripts/test.ps1
    === all 20 checks passed ===

For provider changes, the status page output is the most convincing evidence:

    & "$env:ProgramData\OcspDbProvider\uitest.exe" info -ca '<CA name>'

For installer or script changes, say which mode you ran and on what OS:

    .\ADCS-CDBRP-Provider-Setup-<version>-x64.exe -Mode status
-->

## Impact on an existing installation

<!--
Does an upgraded machine need anything done by hand? Does the configuration file, the
snapshot format, the scheduled task or the install layout change? "None" is a fine answer,
but say it explicitly.
-->

## Checklist

- [ ] `scripts/test.ps1` passes (20/20), and I added an assertion for new behaviour
- [ ] Binary identity is untouched: CLSID `{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}`, ProgID, `OcspDbProvider.dll`, install layout
- [ ] `provider.ini` and the snapshot format stay backward compatible (or a migration is included)
- [ ] No new runtime dependency, and nothing slow or interactive on the `VerifySerialNumber` path
- [ ] PowerShell scripts are still ASCII-only; any `.rc` change is still UTF-16LE
- [ ] No binaries, snapshots, keys or personal paths in the diff
- [ ] Documentation updated, and `docs/RELEASE-NOTES-<next version>.md` mentions user-visible changes
