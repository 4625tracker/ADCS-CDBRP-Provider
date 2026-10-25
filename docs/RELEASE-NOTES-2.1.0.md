# OCSP CDBRP Provider 2.1.0

Multi-CA 配置界面 + 状态页自诊断。

<sub>**English summary.** This release adds a standalone multi-CA configuration tool
(`OcspConfig.exe`), shares the configuration model between the provider and that tool, and
makes the responder status page explain *why* a snapshot shows 0 entries.</sub>

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
Get-FileHash .\OCSP-CDBRP-Provider-Setup-2.1.0-x64.exe -Algorithm SHA256
# 与 SHA256SUMS.txt 中对应行比较
```
