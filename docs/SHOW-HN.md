# Show HN 稿件（成稿，可直接粘贴）

> 目标不是"上榜"，是**被那几十个真正跑 AD CS 的人看到**，并且让他们愿意点进 README。
> HN 的读者对营销词极度敏感，对"我踩了哪些坑"极度宽容 —— 所以正文全部用来讲坑。

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

## 2. 第一条评论（作者自述，粘贴这个）

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

## 3. 预判问题（评论区十有八九会问这些，提前想好）

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

## 4. 规矩（别踩）

- 不要请人 upvote，不要转发到自己小号。
- 不要在标题/正文里放"star my repo"。
- 第一次没反应**不要连发**；隔一周可以换个标题重发一次，这是 HN 容忍的上限。
- 评论里被质疑时，先承认边界（"这个我没测过"），再解释 —— 硬顶会掉到 -1 没人再看见你。
- 有人在评论里复现出问题，比 100 个 upvote 有价值；当场道谢并开 issue。

## 5. 发完之后

- 把有价值的评论整理成 issue（尤其"在大 CA 上会不会炸"这类）。
- 如果上了首页，README 首屏会被大量陌生流量看到——确认第一屏能一眼看懂症状。
- 记录来源：HN 之后一到两周，看 release 的 `download_count` 有没有跳。
