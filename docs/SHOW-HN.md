# Show HN 稿件（骨架 + 素材）

> 目标不是"上榜"，是**被那几十个真正跑 AD CS 的人看到**，并且让他们愿意点进 README。
> HN 的读者对营销词极度敏感，对"我踩了哪些坑"极度宽容 —— 所以正文全部用来讲坑。
>
> **注意：第 2 节那份稿子只当骨架，不要整段粘贴。** Show HN 的隐含要求是"作者本人在场、
> 能答"，往下看第 2.5 节的素材清单，挑 2–3 条用自己的话重写。用 bullet 排得过分整齐、
> 结尾来一句 "happy to answer anything"，反而是最明显的机器味。

## 1. 提交信息

**链接（URL 栏）：**

```
https://github.com/4625tracker/ADCS-CDBRP-Provider
```

**标题（三选一，推荐第一个）：**

```
Show HN: OCSP provider for AD CS that reads the CA database, not the CRL
```

备选（好奇心型，吸引逆向受众，但信息量低一点）：

```
Show HN: I reverse-engineered the Windows Online Responder provider interface
Show HN: Revocation for AD CS without waiting for CRL publication
```

标题规矩：不写感叹号、不全大写、不写 "please upvote"、不放版本号。

**时机：** 周二至周四，美东时间 08:00–10:00（= 北京 20:00–22:00）。发完**至少守两小时**，
前 30 分钟的评论决定它能不能留在首页。

## 2. 素材清单：只有你能写的东西（挑 2–3 条，别全用）

这些都是真实发生过的事故现场，比任何形容词都有说服力。**带错误码、带具体现象**：

| 现象 | 细节 |
|---|---|
| `ocspsvc.exe` 堆损坏 | 把 `GetConfigInformation` 的返回当成字节缓冲，进程崩在 `0xc0000374`；正确形状是 `CERTTRANSBLOB` 里装 `VT_ARRAY\|VT_BSTR` |
| 客户端报 `Bad time value` | `RevStatusInfo` 必须 40 字节紧凑排列，差一个字节所有 FILETIME 就错位 |
| 序列号答案"看着合理但是错的" | 传进来的是字节反序；如果按十六进制**字符**反转，会匹配到别的条目 —— 这种错比直接失败更危险 |
| 安装包起不来，报 SxS 配置错误 | 事件日志里是「invalid Xml syntax line 3」，因为清单文件的 XML 注释里写了 `--` |
| 资源编译把中文路径截断 | 那台服务器机器名就叫「FTP服务器」，`rc.exe` 处理不了非 ASCII 资源路径，只能把 payload 先放到纯 ASCII 的临时目录 |
| MMC 状态页永远显示「0 条」 | 旧版状态文本用的是进程内全局变量，而 `GetStatus` 是被 `mmc.exe` 调用的 —— 那个进程从没查过询，所以计数恒为 0；真实数据是 28 条 |
| 快照一直没生成，看不出原因 | `sync.ps1` 用了 `ProcessStartInfo.ArgumentList`，而它在 Windows PowerShell 5.1 的 .NET Framework 上根本不存在（值为 `$null`） |
| 安装中途中断，服务停着回不来 | `Stop-WebAppPool` 对「已停止的池」抛非终止错误，脚本又开了 `$ErrorActionPreference = 'Stop'` |
| 注册表里的安装目录被写成空的默认值 | `DllRegisterServer` 在注册表没有该值时退回 `%ProgramData%`，并把这个猜测**写了回去**，之后一直指向空目录 |
| `regsvr32` 明明成功却没有退出码 | 在某台机器上它什么都不返回，只能以 `InprocServer32` 的注册表值为准 |

**写法建议：三段，不用 bullet。**

1. 症状：吊销了证书，OCSP 还说 good，等 CRL。
2. 你怎么做的 + **一个**最离谱的坑（带错误码）。
3. 老实说哪里没测过（大 CA、ARM64、非英文/中文 locale、二进制未签名）。

三句话能说完就说完 —— HN 上短而密比长而全高分。

## 3. 骨架稿（参考结构，别整段粘贴）

```
Author here.

The built-in provider (ocsprevp.dll) answers from the CRL, so it inherits CRL latency: revoke
a certificate, and OCSP keeps answering "good" until that CA publishes its next CRL. For a
compromised key that window is the entire problem.

This one answers from the CA database. A scheduled task runs `certutil -view` once a minute and
writes an atomically replaced snapshot; the provider maps serial -> status on the OCSP hot path.
Revocation lands in about a minute. The built-in provider stays registered, so rollback is one
command.

Most of the work was reverse engineering, because IOCSPRevInfoProvider is undocumented. Things
that cost me a day each:

- GetConfigInformation has to return VT_ARRAY|VT_BSTR wrapped in CERTTRANSBLOB (cb holds the
  VARTYPE, pb holds a SAFEARRAY*). Returning a byte buffer looks fine right up until
  ocspsvc.exe corrupts its own heap.
- RevStatusInfo must be exactly 40 bytes, packed. Otherwise every FILETIME is misaligned and
  clients report "bad time value".
- The serial arrives byte-reversed. Reversing the hex string instead of the bytes yields
  plausible but wrong answers, which is worse than failing.
- The configuration is a VARIANT inside a CERTTRANSBLOB, not a text blob.

What it is not: Windows and AD CS only. x64 and x86 builds; ARM64 untested. The binaries are
unsigned. The snapshot comes from parsing certutil output, which I have only exercised on the
English and Chinese locales. And I have run it against one lab CA and one small production CA
(28 rows), so I genuinely do not know how `certutil -view` behaves on a CA with half a million
issued certificates.

Happy to answer anything about the COM contract, the parse format, or the AD CS side.
```

## 4. 预判问题（评论区十有八九会问这些，提前想好）

**Q: 为什么不直接把 CRL 发布周期调短？**
> 那是成本转移，不是解决。CRL 要重新签名、要发布、要分发，客户端还会缓存；把周期从 24h
> 压到 5 分钟意味着 CA 每 5 分钟签一次、CDN 每 5 分钟拉一次。这个方案让 OCSP 不再依赖 CRL
> 发布节奏，CA 的 CRL 周期可以一点都不动。

**Q: 那快照也可能过期，和 CRL 有什么区别？**
> 本质都是"用上一次同步的数据回答"，区别在间隔：CRL 是分钟到小时级不可控，这里是固定
> 一分钟且你能在状态页看到时间戳。这是个诚实的权衡，不是"实时"。

**Q: 解析 certutil 输出，是不是很脆？**
> 是脆，所以按字段形状解析而不是按本地化文案；只在 en 和 zh 上验证过，别的语言没测。
> 解析失败不会写入坏数据：快照是临时文件 + 原子替换，失败就保留上一份，状态页会显示
> 行数和文件时间。

**Q: 大 CA 上 `certutil -view` 每 60 秒跑一次吃得消吗？**
> 不知道，这是我最大的未知。28 行的库上毫秒级；50 万行我没测过。间隔可在
> `provider.ini` 里调（`checkseconds`），任务本身也在 Task Scheduler 里可改。

**Q: 安全问题？谁能写那个 .dat 谁就能决定吊销结果。**
> 对，和"谁能写 CRL 分发点"是同一类风险。安装器只给 NETWORK SERVICE 读权限，写权限留在
> 管理员；威胁模型写在 SECURITY.md 里，没有藏着。

**Q: 为什么不用 C#／托管实现？**
> 这是跑在 ocspsvc.exe 进程内的 in-proc COM 组件，不想给服务器引入 CLR 依赖；`/MT` 静态
> 链接，目标机不需要 VC++ 运行库。

**Q: OCSP 本身在被淘汰（Let's Encrypt 等），值得做吗？**
> 公网侧在退，Windows 企业 PKI 里没有替代品。这个工具解决的是 AD CS 运维的实际痛点，
> 不是押注协议的未来。

**Q: 支持非 ASCII 的 CA 名／机器名吗？**
> 支持，而且是在一台机器名就叫「FTP服务器」的服务器上验证的 —— 这也是当初踩的坑之一：
> rc.exe 解析不了含非 ASCII 字符的资源路径，所以构建时把 payload 放到纯 ASCII 的临时目录。

**Q: ARM64 呢？**
> 代码里加了 `/MACHINE:ARM64` 分支，但本机没装 ARM64 编译组件，没实测，所以 Release 里
> 不放 ARM64 包 —— 不想给一个自己没跑过的东西。

## 5. 规矩（别踩）

- 不要请人 upvote，不要转发到自己小号。
- 不要在标题/正文里放"star my repo"。
- 第一次没反应**不要连发**；隔一周可以换个标题重发一次，这是 HN 容忍的上限。
- 评论里被质疑时，先承认边界（"这个我没测过"），再解释 —— 硬顶会掉到 -1 没人再看见你。
- 有人在评论里复现出问题，比 100 个 upvote 有价值；当场道谢并开 issue。

## 6. 发完之后

- 把有价值的评论整理成 issue（尤其"在大 CA 上会不会炸"这类）。
- 如果上了首页，README 首屏会被大量陌生流量看到——确认第一屏能一眼看懂症状。
- 记录来源：HN 之后一到两周，看 release 的 `download_count` 有没有跳。
