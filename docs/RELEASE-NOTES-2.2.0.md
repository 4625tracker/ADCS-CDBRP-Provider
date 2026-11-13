# ADCS CDBRP Provider 2.2.0

这个版本只解决两件事：**设置界面终于按"你真正会调的东西"重排**，以及
**在已经装过的机器上再跑一次安装器就会自动重装**。

## 设置界面：两组，只留该调的

以前每个 CA 的右侧是一整列平铺的输入框，其中最显眼的是三个状态码
（`validstatus` / `revokedstatus` / `unknownstatus`）。那三个值几乎没人改，却占了最贵的位置，
而真正天天要看的"答复多久过期"反而藏在"缓存秒数"这种含糊名字后面。

现在是两组：

| 组 | 内容 |
|---|---|
| **CA 与快照** | CA 名称、快照文件（含浏览…）、检查间隔（秒）、以及该 CA 的快照状态：解析后的路径、文件是否存在、大小、可解析记录数、修改时间、**上次写入：N 秒前** |
| **OCSP 应答** | 响应有效期（`responseseconds`）+ `10 / 20 / 30 / 60` 预设按钮 + 一句算好的"客户端最迟约 N 秒后看到新的吊销状态" |

三个状态码**从界面移走**，只留在 `provider.ini` 里。这不只是搬家：

- 保存时不再回写状态码 —— 界面先取 `ConfigEffectiveFor(ca)` 的有效值，只覆盖
  snapshot / checkseconds / responseseconds，所以**手写在 ini 里的映射不会被 GUI 冲掉**；
- 想改状态码仍然有命令行的路子：`OcspConfig.exe --set <CA> --valid 0 --revoked 1 --unknown 2`。

状态框里多了一行"上次写入：N 秒前"，超过 180 秒会直接提示"同步任务可能已经停止" ——
这是"吊销比预期慢"最常见的原因，以前只能自己去翻文件时间。

另外，保存后的提示改成了实事求是的一句话：**约 2 秒内自动生效（按修改时间重载，不需要重启
`OCSPSvc`）**。2.1.1 起 `provider.ini` 就是按 mtime 热重载的，界面以前没说清楚。

提供程序自己那个属性页（`rundll32` / 服务管理器里点开的那张）做了同样的处理：数据源保留，
原来的"状态码映射"组换成"OCSP 应答"，同样只写 `responseseconds`。

## 安装：已装过就自动重装

以前"重装"只能先卸载再装，而卸载会连带清掉 `provider.ini` 和快照。现在安装器会先看一眼这台机器：

```
$ .\ADCS-CDBRP-Provider-Setup-2.2.0-x64.exe -Mode detect
ADCS CDBRP Provider Setup 2.2.0 (x64)

installation : present (install becomes a reinstall)
install dir  : C:\ProgramData\OcspDbProvider
COM server   : C:\ProgramData\OcspDbProvider\OcspDbProvider.dll
provider.ini : present
responder    : this provider is active
```

判定依据只有两条：`HKCR\CLSID\{7B0C4B1E-…}\InprocServer32` 指向的 DLL 是否存在，以及
`HKLM\SOFTWARE\OcspDbProvider\InstallDir` 是否存在。命中任意一条，`-Mode install` 就自动走重装
（也可以显式 `-Reinstall`，或 `-Mode reinstall`）。

重装做的是：

1. 备份 `provider.ini` 到 `<InstallDir>\backup\provider.ini.bak-<时间戳>`；
2. 停 `OCSPSvc`，替换 DLL（仍被映射的旧 DLL 就地改名成
   `OcspDbProvider.dll.locked-<时间戳>-<n>`，只保留最新两个）；
3. 重新注册 COM 并**校验** `InprocServer32` 确实指向新路径；
4. `provider.ini` 与快照**原样保留**（`Write-Ini` 见到已存在的文件就跳过）；
5. 重建计划任务、重启服务；
6. 如果响应程序本来就指向本提供程序，重启后自动用上新 DLL，不需要再跑 `-Mode activate`；
7. 最后跑一次 `uitest.exe info` 做健康检查 —— 提供程序初始化不了会直接报出来，而不是装完看起来
   正常、实际全 500。

安装时还会校验 CA 名字：解析出来的 CA 必须出现在响应程序已配置的 CA 列表里（且不能是单个字符这种
明显被传输破坏的值），否则直接报错退出，并提示用 `-CAConfig 'HOST\CAName'` 显式指定。原因是
CA 名字一旦被写坏（例如变成 `[ca:N]`），安装会"成功"但快照名对不上、提供程序对每张证书都答
`unknown`，而界面和日志看起来一切正常。

`-Mode detect` 是同一套判定的只读版本：不提权、不解包、不改任何东西，适合先确认状态。

## 升级

```powershell
ADCS-CDBRP-Provider-Setup-2.2.0-x64.exe            # 已装过 → 自动重装，配置与快照保留
```

2.1.x 升上来不需要先卸载。`provider.ini`、快照文件、CLSID、注册表布局都没变；唯一的差别是
新界面不再显示三个状态码（值仍在 ini 里，行为完全一样）。

## 已知限制

- 重装的健康检查依赖 `uitest.exe`，它随安装包一起更新；如果手工删掉了 `uitest.exe`，重装会在
  验证这一步报错而不是静默跳过。
- 自动重装只在**同一台机器**上判定。把安装目录拷到另一台机器（未注册 COM）仍按全新安装处理。
- 任务计划不能快于 1 分钟重复，刷新节奏靠多触发器叠加；`-SyncPerMinute` 上限仍是 6。
- **OCSP nonce 不支持**：带 `id-pkix-ocsp-nonce` 的请求固定回 `unauthorized(6)`（5 字节
  `30 03 0A 01 06`），这是响应程序自身的策略，请求根本到不了提供程序。openssl 测试请加
  `-no_nonce`。见 [OCSP-NONCE.md](OCSP-NONCE.md)。
- ARM64 仍未实测，所以不提供 ARM64 包。

## 完整变更

- `OcspConfig.exe` 对话框重排为「CA 与快照」+「OCSP 应答」两组，新增响应有效期预设按钮与延迟提示
- 状态码从 GUI 移除，保存不再覆盖 ini 里手写的 `validstatus` / `revokedstatus` / `unknownstatus`
- 快照状态增加"响应有效期"与"上次写入：N 秒前"，超过 180 秒给出同步任务告警
- 提供程序属性页同步调整：去掉状态码组，换成只写 `responseseconds` 的「OCSP 应答」
- 安装器新增 `-Mode detect`（只读）与 `-Reinstall`，`-Mode install` 在已安装时自动转为重装
- 重装会备份 `provider.ini`、清理陈旧 `OcspDbProvider.dll.locked-*`（保留最新两个）、并用
  `uitest.exe info` 做健康检查
- 测试新增两条 UI 断言：响应有效期控件存在（`id=2014`）、三个状态码输入框已消失
- `scripts/test.ps1` 加 UTF-8 BOM（原来在 Windows PowerShell 5.1 下会因中文注释解析失败）

---

许可证仍是 MIT。仓库不含任何微软二进制文件。
