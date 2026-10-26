# 发布与推广手册（LAUNCH.md）

给未来的自己看的。核心结论先写在这儿：

> **这个项目不会有"流量"。** 受众是「在生产环境跑 AD CS Online Responder、并且被 CRL
> 发布延迟坑过的人」，全球量级几千人。目标不是爆款，而是在别人搜到症状的那一刻能被搜到。
>
> 所以宣传 = **内容 + 入口 + 到需求现场**，不是发广告。

---

## 0. 现在的状态（2026-10-25）

- 仓库刚建，0 star / 0 fork 是**算术结果**，不是质量问题：还没在任何地方出现过。
- About、topics、两个 Release、README 双语、社区健康文件都齐了，门面不缺。
- 缺的是：**一个把陌生人带进来的入口**，以及**一篇值得被转发的技术内容**。

## 1. 优先级（按杠杆从高到低）

| 优先级 | 动作 | 为什么 |
|---|---|---|
| ★★★ | 把逆向笔记写成一篇独立文章 | 这是唯一有传播力的资产；工具是它的副产品 |
| ★★★ | 去 ServerFault / Microsoft Q&A / r/sysadmin 回答真实问题 | 需求正在发生的现场，转化率最高，且不算广告 |
| ★★ | Hacker News 的 Show HN（以逆向故事切入） | 受众是工程师，认技术细节，不认营销词 |
| ★★ | 中文侧：V2EX「分享创造」+ 知乎专栏 | AD CS/PKI 中文内容极稀缺，几乎没有竞争 |
| ★ | awesome-pki / awesome-active-directory 之类列表 PR | 长期被动入口 |
| ★ | 给相关 issue 留言（有人问「能不能从 CA 数据库直接出 OCSP」时） | 精准，但必须真的相关，否则是 spam |

**不要做**：群发、到处贴二维码、求 star、在无关 PR 里塞链接。这个圈子很小，一次 spam 就废了。

## 2. 一句话定位（不同场合用不同版本）

**给管理员（症状切入）：**
> 证书在 CA 里吊销了，OCSP 却还返回 good，直到下一次 CRL 发布——这个 AD CS 吊销提供程序直接从 CA 数据库取状态，大约一分钟生效。

**给工程师（机制切入）：**
> A native COM revocation provider for AD CS Online Responder that answers OCSP from the CA database instead of the CRL. Ships with notes on the undocumented `IOCSPRevInfoProvider` contract.

**中文一句话：**
> 给 AD CS 联机响应程序用的吊销提供程序：吊销状态直接取自 CA 数据库，不用等 CRL 发布。

## 3. 英文：Show HN（技术切入）

> **成稿见 [SHOW-HN.md](SHOW-HN.md)** —— 标题、可直接粘贴的第一条评论、九个预判问答、
> 发帖时机与规矩。下面是早期草稿，保留仅作参考。

标题候选：

- `Show HN: OCSP provider that reads the AD CS CA database instead of the CRL`
- `Show HN: I reverse-engineered the Windows Online Responder provider contract`

正文（挑一个，别贪心，一段 + 几条要点）：

```
The Online Responder in AD CS answers OCSP from the CRL. So if you revoke a cert, an OCSP
client can still be told "good" until the next CRL is published — which is exactly when
you needed the answer to be "revoked".

I wrote a revocation provider that reads the CA database instead (certutil -view output,
snapshotted every minute). Revocation shows up in about a minute.

The interesting part was the COM contract: IOCSPRevInfoProvider is not documented.
Some things I had to find by crashing ocspsvc.exe:

- GetConfigInformation returns a VARIANT carried inside CERTTRANSBLOB (cb holds the VARTYPE,
  pb holds a SAFEARRAY*) — returning a byte buffer instead corrupts the heap.
- RevStatusInfo must be exactly 40 bytes packed, or every FILETIME field is misaligned.
- The manager's GetStatus must be VT_ARRAY|VT_BSTR; a single BSTR crashes the MMC snap-in.
- The serial arrives byte-reversed.

Notes are in docs/REVERSE-ENGINEERING.md. Code is C++ with no dependencies, MIT.
```

要点：**先讲问题，再讲你踩到的硬细节，最后一行才给链接**。HN 讨厌开头就放链接的帖子。

## 4. 英文：r/sysadmin 风格（症状切入）

标题：`A cert revoked in AD CS still answers OCSP "good" until the next CRL — I got tired of it`

正文：只讲场景和结果，不贴长文。

```
Ran into this twice: certificate compromised, revoked in the CA, OCSP keeps saying good
because the CRL for that CA hasn't republished yet.

Put together a custom revocation provider for the Online Responder that reads the CA
database directly (snapshot refreshed every minute), so revocation lands in ~1 min instead
of waiting for CRL publication.

Deployment is one installer, keeps the built-in CRL provider registered so rollback is a
single command. Write-up and the reverse-engineering notes are in the repo:
https://github.com/4625tracker/ADCS-CDBRP-Provider

Happy to answer questions about the parse format or the AD CS side.
```

## 5. 最有用的动作：回答别人已经在问的问题

搜索这些关键词，按时间排序，挑**没有好答案**的问题回答：

```
site:serverfault.com OCSP revoked certificate still good
site:learn.microsoft.com "Online Responder" CRL delay revoked
site:reddit.com/r/sysadmin OCSP not reflecting revocation
"ocspsvc" revoked not showing
"Online Responder" custom provider
```

**规矩：先给出可执行的答案（怎么排查、怎么确认、怎么绕），最后再提一句"我写了个工具做这件事"。**
如果答案本身不需要这个工具，就别放链接。这条守住了，长期才有人信你。

## 6. 中文：V2EX / 知乎

V2EX「分享创造」标题：
`[分享] 给 AD CS 联机响应程序写了个吊销提供程序，吊销后 1 分钟就生效`
正文短、带图（MMC 状态页 + 一次真实 OCSP 响应），结尾放仓库。

知乎专栏（拆成系列更好，每篇解决一个问题）：

1. 《AD CS 吊销了证书，OCSP 为什么还说 good？》
2. 《逆向 Windows Online Responder 的未公开 COM 接口》
3. 《用 certutil -view 做一张吊销快照：格式、坑与性能》

第 1 篇是入口（搜症状的人多），第 2 篇是传播（同行会转），第 3 篇是沉淀。

看雪 / 先知：只发第 2 篇的深度版，那边看重技术密度，别带推广语气。

## 7. 七天节奏（别一次全发完）

| 天 | 动作 |
|---|---|
| D1 | 配好 About / topics / homepage；README 首屏确认能一眼看懂「解决什么问题」 |
| D2 | 发第 1 篇中文文章（症状切入），同步 V2EX |
| D3 | 发第 2 篇（逆向），投看雪/先知；英文版准备 |
| D4 | Show HN（美东时间早上 8-10 点发，发完两小时守着回评论） |
| D5 | r/sysadmin + r/ActiveDirectory |
| D6 | 去 ServerFault / Microsoft Q&A 回答 3-5 个真实问题 |
| D7 | 复盘：哪条带来了提问/issue，就把那条的渠道再写一篇 |

## 8. 衡量指标（别看 star）

- **有人复现并提问** —— 这是唯一有意义的信号
- issue 里出现他们自己的环境细节（CA 名、快照路径、错误码）
- Release 下载数（GitHub 会显示 `download_count`）
- 被别的文档/文章引用

star 是滞后指标，而且这个细分的天花板本来就低。**一个真的部署了的管理员，比 500 个 star 有用。**

## 9. 素材清单（发帖前准备好）

- [ ] MMC 里「吊销提供程序状态」的截图，要能看见路径、字节数、**28 条记录**（这是最有力的证据）
- [ ] 一次真实 OCSP 请求的前后对比：`certStatus=revoked`
- [ ] 一张「CRL 时间线 vs 本方案」的简图（可选，但对管理员很有效）
- [ ] 安装/回滚各一条命令（让人相信可以安全试用）
- [ ] 一个 30 秒能读完的 README 首屏

最后一条可能需要重写首屏。现在的 README 开头是「A native COM revocation provider…」——
那是**给已经知道自己在找什么的人**看的。搜症状进来的人需要先看到
「证书吊销了但 OCSP 还说 good」这句。
