# ADCS CDBRP Provider 2.1.0

Multi-CA 配置界面 + 状态页自诊断。

> **项目更名为 `ADCS-CDBRP-Provider`。** `CDBRP` = **C**A **D**atabase **B**ased **R**evocation
> **P**rovider，即「基于证书数据库的吊销提供程序」。安装包文件名随之变为
> `ADCS-CDBRP-Provider-Setup-<version>-<arch>.exe`。
> CLSID、ProgID、`OcspDbProvider.dll`、安装目录、`provider.ini` 与快照格式**都没有变**，
> 已部署的机器升级不受影响。

<sub>**English summary.** This release adds a standalone multi-CA configuration tool
(`OcspConfig.exe`), shares the configuration model between the provider and that tool, and
makes the responder status page explain *why* a snapshot shows 0 entries. The project is now
named `ADCS-CDBRP-Provider` — CDBRP stands for *CA Database Based Revocation Provider* — while
binary identity (CLSID, ProgID, DLL name, install layout) is unchanged.</sub>

## 新增：多 CA 配置界面（OcspConfig.exe）

安装完成后在 `%ProgramData%\OcspDbProvider\OcspConfig.exe`（开始菜单/资源管理器直接双击即可，
**不需要管理员**——只有写 `provider.ini` 时需要对该目录有写权限）。

- 左侧列出所有「已知 CA」：响应程序里配置过的 CA + `provider.ini` 里已有分段的 CA，并标注
  `[响应程序]` / `[已配置]`；
- 选中任意 CA，右侧编辑它的 **快照文件 / 缓存秒数 / 有效·已吊销·未知道 三个状态码**；
- 下方实时显示该 CA 的快照状态：解析到的路径、文件是否存在、字节数、可解析行数、修改时间；
- 「保存」只写该 CA 的分段，「删除」只删该 CA 的分段，不会碰响应程序自身的配置。

命令行（便于批量/自动化）：

```powershell
OcspConfig.exe --dump
OcspConfig.exe --set CORP-A --snapshot C:\data\CORP-A.dat --unknown 2
OcspConfig.exe --remove CORP-B
```

`--dump` 输出示例：

```
CA                           source   check  valid  revoked  unk    rows    snapshot
CORP-A                       ini      0      0      1        9      2       C:\ProgramData\OcspDbProvider\data\CORP-A.dat
CORP-B                       both     2      0      1        7      1       C:\ProgramData\OcspDbProvider\data\CORP-B.dat
```

## 新增：配置模型共享

`provider.ini` 的解析与写回抽到 `OcspDbConfig.cpp`，提供程序（DLL）与配置工具（EXE）编译同一份
实现，不会出现「工具写的东西提供程序读不懂」。现有的平铺/分段配置格式完全不变，是超集兼容。

## 改进：状态页能自己解释「0 条记录」

以前状态页只显示「快照记录：0 条 / 最后加载：(尚未加载)」，看不出是路径不对、文件是空的，还是
导出格式不对。现在会额外显示：

- **快照文件**：提供程序真正解析出的完整路径（多 CA 时最常错的地方）
- **文件状态**：存在 / 不存在，以及字节数
- 记录数为 0 时给出一条针对性提示（路径无文件 / 0 字节 / 有内容但无可解析行）

> 你之前截图里那种「有文件时间、但 0 条」的情形，现在会直接告诉你文件是 0 字节还是有内容但
> 解析不出行。

## 修复

以下都是这次在真实服务器上部署时暴露出来的：

- **计划任务根本没有触发器**：`install.ps1` 调用 `Register-ScheduledTask` 时没传 `-Trigger`，
  生成的任务是空的 `<Triggers />`，从来不运行 —— 快照永远停在安装那一刻。现在用任务 XML
  显式写 `TimeTrigger` + `Repetition Interval PT1M`（不带 `Duration` 才是"无限重复"），
  注册后还会断言 `Triggers.Count > 0` 且 `NextRunTime` 有值。
- **计划任务里的 CA 名被破坏**：任务动作把中文 CA 名当参数传递，而无 BOM 的 UTF-8 脚本被
  PowerShell 5.1 按 ANSI 读取，一个多字节序列把后面的反斜杠吃掉了，于是 `sync.ps1` 认为这个
  名字没有主机前缀、又加了一次，变成 `服务器\服务器\CA`，`certutil` 每次都以
  `E_INVALIDARG (0x80070057)` 失败。现在任务动作**不带 CA 名**，由 `sync.ps1` 从响应程序
  注册表解析。
- **响应程序把答复缓存半小时**：`nextUpdate` 硬编码为 `now + 30 分钟`，而响应程序和客户端就
  按这个时间缓存答复 —— 快照明明已经更新，OCSP 仍返回半小时前的旧答复。新增 `responseseconds`
  配置项（默认 60），`nextUpdate = now + responseseconds`。**实测端到端 62 秒**：往快照里
  注入一条吊销记录后，OCSP 在 62 秒后变成 `revoked`。
- **`DllRegisterServer` 曾把默认安装目录写进注册表**。注册表还没有 `InstallDir` 值时它退回
  `%ProgramData%\OcspDbProvider`，于是把「猜出来的默认值」写成了事实，之后一直指向那个空目录 ——
  这就是状态页显示 0 条的直接原因。现在以 DLL 自身所在目录为准，安装脚本也会显式写入并校验。
- **升级时旧 DLL 被 `ocspsvc.exe` / 打开的 MMC 占用，复制失败**。现在安装脚本会自动把旧 DLL
  改名挪开再放新的（重命名不受文件映射影响），并在下一次加载时生效。
- **`sync.ps1` 在 Windows PowerShell 5.1 上崩溃**：用了只有 PowerShell 7 才有的
  `ProcessStartInfo.ArgumentList`（5.1 上为 `$null`），导致快照一直没生成。
- **`install.ps1` 在服务已停止时被中断**：`Stop-WebAppPool` 会抛非终止错误，而脚本开了
  `$ErrorActionPreference='Stop'`，整条安装流程被提前打断。
- **`regsvr32` 在部分主机上不返回退出码**，导致安装误判失败；改为以 `InprocServer32` 和
  `InstallDir` 的注册表值为准，`regsvr32` 只作参考。
- 计划任务名与快照文件名改用裸 CA 名（之前用「主机名\CA」，会生成
  `FTP____NAS-Monitor-CA` 这类名字，且与提供程序按 CA id 推导的默认路径不一致）。
- `OcspConfig.exe` 的 `--dump` 输出在重定向到文件时出现 `\r\r\n`（stdout 文本模式重复翻译换行）。

## 升级说明

- 安装包现在多装一个 `OcspConfig.exe`，其余行为不变；
- `provider.ini` **不会被覆盖**；
- 改完配置后仍需 `Restart-Service OCSPSvc` 让提供程序重新读取（状态页/工具里也会提示）。

## 兼容性

| 项目 | 说明 |
|---|---|
| CLSID | 不变 `{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}` |
| `provider.ini` | 格式不变（新增能力用同样的 `[ca:<id>]` 分段） |
| 快照文件 | 格式不变 |
| 系统 | Windows 7 / Server 2008 R2 及以上，x64 / x86 |

## 校验

```powershell
Get-FileHash .\ADCS-CDBRP-Provider-Setup-2.1.0-x64.exe -Algorithm SHA256
# 与 SHA256SUMS.txt 中对应行比较
```
