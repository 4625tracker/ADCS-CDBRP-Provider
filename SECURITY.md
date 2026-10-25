# Security Policy

<sub>**中文摘要**：安全漏洞请走私密渠道——首选 GitHub 的私密漏洞报告
（Security → Report a vulnerability），也可以发邮件到 **fgsh_20100822@outlook.com**
（标题加 `[security]`）。不要开公开 issue。受支持的是最新的 2.x 版本。这个提供程序以 SYSTEM
身份运行在 `ocspsvc.exe` 进程内，能写快照文件或安装目录就等于能改变吊销结果，请按这个前提评估风险。</sub>

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | Yes |
| 2.0.x | Yes (security fixes only) |
| 1.x | No — no longer maintained, and no longer in this repository |

## Reporting a vulnerability

**Do not open a public issue.** Two private channels, both read by the maintainer:

1. **GitHub private advisory (preferred)** — **Security** tab → **Report a vulnerability**
   (<https://github.com/4625tracker/ADCS-CDBRP-Provider/security/advisories/new>).
   Preferred because the discussion, the fix and the credit stay attached to the advisory.
2. **E-mail** — [fgsh_20100822@outlook.com](mailto:fgsh_20100822@outlook.com) with
   `[security]` in the subject, if you would rather not use GitHub.

Please include:

- the provider version (`OcspConfig.exe --dump` or the DLL's file version),
- the Windows version and architecture, and whether the responder runs standalone or behind
  the OCSP ISAPI,
- what an attacker gains, and the preconditions in concrete terms (local user? write access
  to a directory? network position?),
- steps or a script that reproduces it.

This is a personal project maintained in spare time: expect a best-effort response, not an
SLA. You will get an acknowledgement, and credit in the advisory unless you prefer otherwise.

## Scope

In scope:

- the provider DLL and the COM surface it implements,
- the configuration tool, the installer and the PowerShell scripts in `scripts/`,
- parsing of `provider.ini` and of the snapshot file (malformed input must not crash or force
  a `good` answer),
- anything that lets a principal change revocation answers without already holding
  administrator rights on the responder.

Out of scope:

- vulnerabilities in Windows, AD CS, `ocspsvc.exe`, IIS or the CA database itself,
- a CA whose own configuration or permissions are wrong (for example a snapshot that any
  interactive user can rewrite — see the threat model below),
- the fact that the released binaries are **not code-signed** (see below),
- denial of service that requires administrator rights, since an administrator can stop the
  service anyway.

## Threat model, stated plainly

The provider runs **in-process inside `ocspsvc.exe`, as `NETWORK SERVICE`**, reached over COM
from the responder. Two consequences matter:

1. **Write access to the snapshot is equivalent to control over revocation answers.** Whoever
   can modify `%ProgramData%\OcspDbProvider\data\*.dat` (or whatever path `provider.ini`
   points at) decides which certificates are reported revoked. The installer grants
   `NETWORK SERVICE` read/execute on the install directory; keep the directory writable only
   by administrators and SYSTEM.
2. **A snapshot is trusted input.** It is produced by `certutil -view` under the account
   running the scheduled task (`SYSTEM`) and consumed without a signature. If you need
   integrity beyond filesystem ACLs, place the snapshot on a volume or share whose
   permissions you control, and treat `provider.ini` as security-relevant configuration.

The provider never contacts the network, never runs a child process and never reads the CA
private key. It only reads the snapshot file and the configuration file.

## Known limitations (not vulnerabilities, but you should know them)

- **Unsigned binaries.** The setup EXE and the DLL are not code-signed, because a code-signing
  certificate is not available to this project. `SHA256SUMS.txt` is published with every
  release; verify it before running the installer. If you need signed binaries, build them
  yourself — the toolchain is documented in [CONTRIBUTING.md](CONTRIBUTING.md).
- **No snapshot signature.** See the threat model above: ACLs are the only integrity control.
- **The status page is read-only**, but it does read the snapshot and `provider.ini` from
  whatever process displays it (including an unelevated MMC), so those must be readable by
  interactive administrators.
- **`OCSPDBPROVIDER_DIR` and the `HKLM\SOFTWARE\OcspDbProvider\InstallDir` value** redirect
  where the provider looks for its configuration. Both require administrator rights to change;
  they are documented behaviour, not an escalation path.

## Handling of credentials and personal data

The provider stores no credentials and logs no certificate serials beyond a bounded count of
queries; `provider-native.log` records lifecycle events (`Initialize`, snapshot reloads,
`GetStatus` calls) and is written next to the configuration. It is safe to attach to a report
after a glance, but check it for site-specific paths before posting publicly.
