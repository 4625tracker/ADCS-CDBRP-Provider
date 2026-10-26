# 逆向笔记：AD CS 联机响应程序的吊销提供程序接口

> **English abstract.** Reverse engineering notes for the AD CS Online Responder
> (`ocspsvc.exe`) and its revocation provider contract (`IOCSPRevInfoProvider` /
> `IOCSPRevInfoProviderManager`). The interface is **not publicly documented**: the Windows SDK
> ships no OCSP header at all and Microsoft's documentation only names it once (see
> [REFERENCES.md](REFERENCES.md) for the evidence). This document records how the contract was
> recovered, the exact vtable layout, the data shapes that are not what they look like, the
> failure codes each mistake produces, and how to reproduce every claim. Tools: Ghidra on
> unsigned binaries (no PDB), plus a hand-written harness that talks to the real service.
>
> 对象：`C:\Windows\System32\ocsprevp.dll`（内置提供程序）、`ocspsvc.exe`（响应程序服务），
> 均无符号、无 PDB。托管侧 `Microsoft.CertificateAuthority.OcspSnapin.dll` 与
> `OCSPAdminNative.dll` 用来确认 MMC 的期望。

## 0. 七条一句话结论

先看这个，后面都是展开和证据。

| # | 结论 |
|---|---|
| 1 | 提供程序是**进程内 COM**，被 `ocspsvc.exe` 以 **MTA** 加载，只注册 `InprocServer32` 就行 |
| 2 | 两个接口都是 **dual**，自定义方法之后还有 4 个 `IDispatch` 槽位，vtable 布局不能少 |
| 3 | `CERTTRANSBLOB.cb` 在配置路径上装的是 **VARTYPE**，不是字节数；`pb` 是 `SAFEARRAY*` |
| 4 | 配置是一张 **二维 VARIANT 名值对表**（属性名 / 属性值），必须原样回吐 |
| 5 | `RevStatusInfo` 是 **40 字节紧密结构**，偏移 0/4/12/20/28/36，差一个字节时间就全错 |
| 6 | 状态码：**0 = good，1 = revoked，2 = unknown** |
| 7 | 序列号是**字节反序**传进来的；反转十六进制字符串会得到"看起来对但是错"的结果 |

## 1. 范围与免责

这份笔记只记录**可复现的事实**：反汇编里读到的、抓包抓到的、切换实现后现象变化的。
推断会明确标注「推断」，没搞清的进 §10。

它不是微软文档的替代品 —— 恰恰相反，它记录的是**没有文档的那部分**。如果你要写自己的
提供程序，可以照 §9 的步骤一步步验证，不必相信本文的任何断言。

## 2. 起点：服务怎么找到你的 DLL

### 2.1 注册表链路

```
HKLM\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder\<CA 名>
    ProviderCLSID   REG_SZ   {4956D17F-88FD-4198-B287-1E6E65883B19}   ← 内置 CRL 提供程序
```

服务把 `ProviderCLSID` 当 **VT_BSTR** 读出来，`CLSIDFromString`，然后
`CoCreateInstance(..., CLSCTX_INPROC_SERVER, IID_IOCSPRevInfoProvider, ...)`。
也就是说：**改这个值 = 换提供程序**，不需要动 `ocspsvc.exe` 本身。

内置的那份 `ocsprevp.dll` 就直接反汇编它 —— 它和你写的提供程序受同一套规则约束，
是最好的参照物。

### 2.2 从 DLL 到 vtable（`ocsprevp.dll`）

| 项 | 地址 |
|---|---|
| coclass `COCSPRevInfoProvider` CLSID | `{4956D17F-88FD-4198-B287-1E6E65883B19}`（rdata `0x180025e50`）|
| `CreateInstance` | `0x180003970`（ATL 对象表在 `0x18002d000`）|
| 构造函数（设置 vtable） | `0x18000261c` → `*this = &PTR_FUN_180023a38` |
| **vtable** | `0x180023a38` |
| QI / AddRef / Release | `0x180004630` / `0x180002f40` / `0x1800054e0` |
| **Initialize** | `0x18000c730` |
| **VerifySerialNumber** | `0x180010c60` |
| `GetConfigInformation` | `0x18000a9e0` |
| `GetProviderManager` | `0x18000be00` |

对象构造里能看到内部类名：`COCSPConfigMgr` / `CCOCSPRevInfoProvider`（宽字符串，
`0xa11ca11c` 哨兵）。看到 `COCSPConfigMgr` 就说明**管理器和提供程序是两套对象**，
这也解释了为什么 `GetProviderManager` 可以返回同一个单例。

## 3. 方法：改一处、看是崩还是过

逆向这个接口基本靠"行为二分"，因为接口没文档，类型库也没公开。四种现象各自指向一类错误：

| 现象 | 说明什么 |
|---|---|
| `ocspsvc.exe` 崩在 `0xc0000374`（STATUS_HEAP_CORRUPTION） | **数据形状**对了但**所有权**不对（最典型：把 VARIANT 当字节缓冲返回，服务按变体数组释放） |
| `ocspsvc.exe` 崩在 `0xc0000005` | 多半是空指针 / 越界写，先检查 `pb` 是不是被当作裸字节用了 |
| 事件日志 `E_UNEXPECTED (0x8000ffff)`，提示「意外的方法调用顺序」 | **调用顺序**错：在 `Initialize` 之前调了管理器的方法，或拿错了接口指针 |
| OCSP 回 `unauthorized (6)` | 提供程序**加载失败**或配置被判无效（回环没对上），去看事件日志 |

三种可观测面，缺一不可：

1. **事件日志**（Application，来源 `OnlineResponder` / `Application Error`）—— 加载失败、
   崩溃、配置被拒都在这里，且**只有这里**（COM 调用本身不返回错误给 HTTP 层）。
2. **提供程序自己的日志**——本文的实现写 `provider-native.log`，记录 `Initialize`、
   快照重载、`GetStatus` 调用，用来确认「服务到底调了哪个方法、传了什么形状」。
3. **一次真实 OCSP 请求**——`openssl ocsp` 或 `certutil -urlfetch`，看客户端视角的结果。

## 4. `IOCSPRevInfoProvider`

```
IID {93F568FF-B8C7-483B-8DEF-5E6EEF8B7650}
```

### 4.1 vtable 布局（x64，每槽 8 字节）

| 偏移 | 槽位 | 方法 |
|---|---|---|
| `0x00` | 0 | `QueryInterface` |
| `0x08` | 1 | `AddRef` |
| `0x10` | 2 | `Release` |
| `0x18` | 3 | `Initialize` |
| `0x20` | 4 | `VerifySerialNumber` |
| `0x28` | 5 | `GetConfigInformation` |
| `0x30` | 6 | `GetProviderManager` |
| `0x38` | 7 | `GetTypeInfoCount`（`IDispatch`）|
| `0x40` | 8 | `GetTypeInfo` |
| `0x48` | 9 | `GetIDsOfNames` |
| `0x50` | 10 | `Invoke` |

两个接口在类型库里都是 `TKIND_DISPATCH`（dual），所以**自定义方法之后还有四个
`IDispatch` 槽位**。实现时补齐这四槽但返回 `DISP_E_*` 即可 —— 少写会让 vtable 整体错位，
而错位在这个接口上不会给你编译错误，只会给你一次崩溃。

### 4.2 `Initialize(BSTR caId, CERTTRANSBLOB* pCACert, CERTTRANSBLOB* pConfig)`

- **`caId` 是裸 CA 名**（例如 `NAS-Monitor-CA`），不是 `机器名\CA名`。
  注意这个差别：`certutil` 那边要主机前缀，COM 这边不要。写成一样会踩 `0x800706BA`。
- `pCACert` 是 CA 证书的 DER（装在 `CERTTRANSBLOB` 里），本次实现不校验它。
- `pConfig` 是**配置**，形状见 §6.2 —— 如果你把它当文本/字节块读，第一次就崩。
- 返回值：`S_OK` 表示加载成功；返回失败 → 服务记事件、该 CA 的 OCSP 全拒。

**要点：`Initialize` 里不要做重活。** 它在服务启动/配置刷新时被同步调用，快照应当按需
异步加载（本实现在 `GetStatus` / 首次查询时才读文件）。

### 4.3 `VerifySerialNumber(CERTTRANSBLOB* pSerial, RevStatusInfo* pStatus)`

OCSP 热路径，每次查询一次。

- `pSerial`：`cb` = 字节数，`pb` = **字节反序**的序列号（见 §6.5）。
- `pStatus`：服务已经分配好的 40 字节结构，**你只负责填**，不要重新分配、不要写越界。
- 无论查到与否都应返回 `S_OK` 并填好 `dwStatus`；用返回码表示"没这条"会让上层把整个
  提供程序判为故障。

### 4.4 `GetConfigInformation(CERTTRANSBLOB* pConfig)`

返回当前配置，**必须与服务存的那份形状一致**（二维 VARIANT 名值对）。见 §5、§6.2。

`GetConfigInformation` 和 `Initialize` 之间的关系是本项目踩得最久的一个坑：
服务会拿你返回的东西和它存的东西比对，形状/内容对不上就判配置无效。

### 4.5 `GetProviderManager(IUnknown** ppMgr)`

返回 `IOCSPRevInfoProviderManager`。服务用 `QueryInterface` 拿它，之后配置界面、
状态页都走管理器。**返回同一个单例**即可；每次 new 一个也能跑，但会让状态不共享。

## 5. `IOCSPRevInfoProviderManager`

```
IID {F85C5127-F108-497D-8FCC-B2A709047C98}
```

### 5.1 vtable 布局

| 偏移 | 槽位 | 方法 |
|---|---|---|
| `0x00`/`0x08`/`0x10` | 0–2 | `QueryInterface` / `AddRef` / `Release` |
| `0x18` | 3 | `GetProviderInformation` |
| `0x20` | 4 | `Configure` |
| `0x28` | 5 | `View` |
| `0x30` | 6 | `GetStatus` |
| `0x38` | 7 | `Initialize`（类型库里是 `Initialize_`，与提供程序的那同名，注意别混）|
| `0x40`–`0x58` | 8–11 | `GetTypeInfoCount` / `GetTypeInfo` / `GetIDsOfNames` / `Invoke` |

托管侧调用点可以直接印证：`OCSPAdminNative!DllRevProvGetStatus` 里就是
`mgr->vtable[0x30](mgr, caId, &v, pStatus, pHR)` —— 用**偏移**调用，说明它拿的是裸 vtable，
而不是编译期接口。这也解释了为什么少一个槽位会崩在完全无关的地方。

### 5.2 `GetProviderInformation(BSTR* name, BSTR* desc)`

显示在 MMC「吊销配置 → 提供程序」列表里的名称与描述。中文/英文各一套，本实现按系统
UI 语言切换（`OCSPDBPROVIDER_LANG=zh|en` 可强制）。

### 5.3 `Configure(hwnd, caId, pCACert, pIn, BOOL* pModified, pOut)`

MMC 里点「属性」时调。`pIn` 是现有配置，`pOut` 是用户改完后的新配置；
`*pModified` 决定服务是否落盘。实现要点：

- 对话框里**不要直接写自己的配置文件**再指望服务保存 —— 两边都写会打架；
- `pOut` 的形状必须和 `pIn` 一致（同样是二维 VARIANT 名值对），否则服务存进去的东西
  下次 `Initialize` 就解不出来。

### 5.4 `View(hwnd, caId, pCACert, pIn)`

只读视图（MMC 里的「查看提供程序属性」）。本实现复用同一个对话框、禁用输入。

### 5.5 `GetStatus(caId, pCACert, pIn, VARIANT* pStatus, HRESULT* pHR)`

MMC 状态页那几行文字。

- **`pStatus` 必须是 `VT_ARRAY | VT_BSTR`（BSTR 数组）**，见 §7.2；
- `pHR` 是出参，用于把内部错误码带给 MMC；
- 这几行文字要**在任意进程里都能独立算出来** —— 这条是 §7.3 那个 bug 的教训。

### 5.6 `Initialize_(caId, pCACert, pOut)`

管理器侧的初始化，服务在挂载 CA 配置时调。它与提供程序侧的 `Initialize` 不是一回事：
提供程序侧拿到的是"要服务哪些查询"，管理器侧拿到的是"要显示/编辑哪份配置"。

## 6. 数据契约

### 6.1 `CERTTRANSBLOB` 的真实用法

定义本身很朴素（见 [MS-CSRA 2.2.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/a94fb0b1-902f-43ea-9422-f2d24bcb10b6)）：

```c
typedef struct _CERTTRANSBLOB { ULONG cb; [size_is(cb)] BYTE* pb; } CERTTRANSBLOB;
```

但在这个接口上，**`cb` 经常不是长度，而是 `VARTYPE`**：

| `cb` | 含义 | `pb` 实际指向 |
|---|---|---|
| `0x200C` | `VT_ARRAY \| VT_VARIANT` | `SAFEARRAY*`（二维：属性名 / 属性值）|
| `0x2011` | `VT_ARRAY \| VT_UI1` | `SAFEARRAY*`（一维字节数组）|
| `0x0008` | `VT_BSTR` | `BSTR` |

证据在 `ocsprevp.dll` 的 `FUN_18001bed8`（被 `GetConfigInformation` 调用）：

```c
local_res20 = (longlong *)param_1[1];
if (local_res20 < 0x10001) {
    local_38.cElements = (ULONG)local_res20;
    psa = SafeArrayCreate(0xc /* VT_VARIANT */, 2, &local_38);   // 2 维
    *param_2 = 0x200C;                    // ← cb 里放 VARTYPE
    *(SAFEARRAY **)(param_2 + 4) = psa;   // ← pb 里放 SAFEARRAY*
}
```

**后果**：如果按"字节缓冲"处理（自己 malloc 一段、塞进 `pb`），服务会按变体数组去释放它 ——
堆结构被破坏，`ocspsvc.exe` 崩在 `0xc0000374`。这个崩溃点离你的代码很远，第一眼看不出是谁。

### 6.2 配置 = 二维 VARIANT 名值对

形状：`SAFEARRAY(VT_VARIANT, 2 维)`，每行 `[属性名, 属性值]`，两列。

这与官方文档对 `IOCSPCAConfiguration::ProviderProperties` 的描述完全对得上：

> "The VARIANT returned in *pVal* is a pointer to a safe array ... a **two-dimensional array**
> of elements, each of type VARIANT. The array contains **one row for each named property** ...
> Each row contains two columns: **the property name and the property value**."
>
> —— [get_ProviderProperties](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_providerproperties)

同一页还给出了内置提供程序的属性名：`BaseCrl`、`BaseCrlUrls`、`CrlUrlTimeout`、
`DeltaCrl`、`DeltaCrlUrls`、`RefreshTimeOut`、`RevocationErrorCode`、
`IssuedSerialNumbersDirectories`。

**这解释了那个「中间层」的坑**：管理侧的 `ProviderProperties` 和运行侧
`Initialize`/`GetConfigInformation` 用的是**同一个 VARIANT**，只是外面套了个
`CERTTRANSBLOB`。于是：

- 读配置：`pb` 是 `SAFEARRAY*`，按二维数组取行列；
- 写配置：必须造出同样形状的数组再塞回 `pb`；
- **回环一致性**：`GetConfigInformation` 吐回的东西要和 `Initialize` 收到的等价，
  否则服务判配置无效。

本项目早期草稿忽略了传入 blob、自己拼字符串返回，结果是配置被判无效 →
OCSP 全量 `unauthorized (6)`。改成"原样回吐"后，失败从 `unauthorized` 变成 `500`，
说明配置这一关过了（`500` 是后面的数据问题）。

### 6.3 `RevStatusInfo`：40 字节，一个都不能多

`VerifySerialNumber` 里对 `param_3` 的写操作（`param_3` 是 `DWORD*`，按 4 字节步进）：

```
param_3[0]          = 0 / 1 / 2      // dwStatus
*(u64*)(param_3+1)  = thisUpdate      // +4
*(u64*)(param_3+3)  = nextUpdate      // +12
*(u64*)(param_3+5)  = nextPublish     // +20
*(u64*)(param_3+7)  = entry+0x10      // +28  ftRevocationDate
param_3[9]          = reason          // +36  dwRevocationReason
```

| 偏移 | 字段 | 类型 |
|---|---|---|
| 0 | `dwStatus` | `DWORD` |
| 4 | `ftThisUpdate` | `FILETIME` |
| 12 | `ftNextUpdate` | `FILETIME` |
| 20 | `ftNextPublish` | `FILETIME` |
| 28 | `ftRevocationDate` | `FILETIME` |
| 36 | `dwRevocationReason` | `DWORD` |

**总长 40 字节，紧密排列，无填充。** C++ 侧 `#pragma pack(push,1)`，C# 侧
`[StructLayout(LayoutKind.Sequential, Pack = 1)]`。

按 8 字节对齐会插 4 字节填充、变 48 字节，之后每个时间字段整体错位 4 字节 ——
客户端看到的是 `This Update: Bad time value`，而你的代码一行都没错。这类错误最难查。

### 6.4 状态码

| 值 | 含义 | 备注 |
|---|---|---|
| 0 | good | 快照里没有该序列号时通常返回这个（等价 CRL 语义）|
| 1 | revoked | 必须同时填 `ftRevocationDate` 与 `dwRevocationReason` |
| 2 | unknown | "在某列表里没找到"，语义比 good 弱 |

本实现允许**每个 CA 单独映射**这三个值（`provider.ini` 的 `validstatus` /
`revokedstatus` / `unknownstatus`），因为不同 CA 的运维约定不一样。

### 6.5 序列号编码：反转字节，不是反转字符串

抓到的实参：

```
cb = 19
bytes = 03 00 00 00 00 00 4D 41 50 6F 25 41 41 CC 03 00 ...
```

库里该证书的序列号（`certutil -view` 的 SerialNumber 列）：

```
62 00 00 00 03 CC 41 41 25 6F 50 41 4D 00 00 00 00 00 03
```

按**字节**反转后完全吻合 —— 等价于按小端存放。

⚠️ 注意是反转**字节**。如果反转的是**十六进制字符串**，在奇数长度（或前导零）的序列号上
会得到不同的结果，而且是"看起来合理但是错"的那种：匹配到别的证书、或把已吊销的判成 good。
**失败的查询比错误的查询安全**，这个坑值得单独写测试。

### 6.6 时间字段从哪来（含未解）

- `ftThisUpdate`：本次回答的时刻（`now`）
- `ftNextUpdate`：`now + 30 分钟` —— 实测与 MMC 状态页显示一致
- `ftNextPublish`：`now + 120 分钟` —— **这是本实现的取值，不是从数据推导出来的**。
  反汇编里没有证据表明服务对它有特定期望；选一个比 `nextUpdate` 更晚的时刻可以让缓存行为
  更宽松。如果你要在意它，先做实验再照抄。
- `ftRevocationDate` / `dwRevocationReason`：来自数据库行的 `RevokedWhen` / `RevokedReason`

## 7. 生命周期、线程与进程边界

### 7.1 服务侧如何加载（`ocspsvc.exe`）

`FUN_140012eb8`：

```c
if (prop.vt == 8) {                                  // VT_BSTR = ProviderCLSID
    CLSIDFromString(prop.bstrVal, &clsid);
    hr = CoInitializeEx(NULL, 0);                    // 0 = COINIT_MULTITHREADED
    if (hr < 0) → 失败（事件 0xD34089B）
    hr = CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IOCSPRevInfoProvider, &obj+0x58);
    if (hr != 0) → 失败（事件 0xD3D089B）
}
```

要点：

- **MTA**，不是 STA。提供程序必须线程安全；本实现用一把临界区保护快照缓存。
- 只用 `CLSCTX_INPROC_SERVER`，所以必须写 `InprocServer32`（`regsvr32` 即可）。
- **加载失败只写事件日志**，不返回给 HTTP 层 —— 上层表现就是所有请求 `unauthorized (6)`，
  很容易被误判成 ACL 问题。

### 7.2 为什么 `pStatus` 必须是 `string[]`

反编译托管 snapin 与 native 中间层后定位：

```csharp
// Microsoft.CertificateAuthority.OcspSnapin!RevProvMgr.RevProvGetStatus
DllRevProvGetStatus(...);
status = (String[])obj;          // ← castclass String[]
```

```c
// OCSPAdminNative!DllRevProvGetStatus
SAFEARRAY *sa = SafeArrayCreate(VT_UI1, 1, &bound);   // 配置按 VT_ARRAY|VT_UI1(0x2011) 传入
mgr = GetManager(providerClsid);                       // CoCreate + vtable[0x30]
mgr->vtable[0x30](mgr, caId, &v, pStatus, pHR);        // 0x30 = GetStatus
```

返回单个 `VT_BSTR` 时，托管侧 `castclass String[]` 抛 `InvalidCastException`；
而 `OCSPError::IsExceptionUnRecoverable` 把非白名单异常判为**不可恢复**并重抛，
于是 `mmc.exe` 直接退出。改成 BSTR 数组后：`mmc alive=True crashes=0`。

**附带教训：MMC 自己的报错会吞掉真实错误。** `SnapInNode._OnActionWrapper` 里只要抛异常，
`OCSPErrorImpl.ShowExceptionError` 自己也会抛，最后你只看到 MMC 崩了、没有任何信息。
排查这类问题**不要依赖 MMC 的报错**，去看事件日志或用 `uitest.exe` 直接调。

### 7.3 同一个 DLL，两个宿主进程

这个 DLL 会被加载进**至少两个进程**：

| 进程 | 用途 | 状态 |
|---|---|---|
| `ocspsvc.exe` | 真正回答 OCSP | 有 `Initialize`、有查询计数 |
| `mmc.exe` | 配置界面、状态页 | 只调 `GetStatus` / `View`，从没 `VerifySerialNumber` 过 |

所以**状态不能只存在进程内全局变量里**。早期的状态页就是踩了这个：
`GetStatus` 在 `mmc.exe` 里读全局计数，那个进程从没初始化过，于是永远显示
「快照记录：0 条 / 最后加载：（尚未加载）」—— 而服务进程里其实是 28 条。

修法：状态页**按需重建**（该 CA 的快照对象懒加载、退出即弃），不依赖任何进程级累积值。
现在的状态页在 `mmc.exe` 里也能显示真实行数、文件字节数和修改时间。

## 8. 失败模式速查

| 现象 | 根因 | 怎么确认 |
|---|---|---|
| `ocspsvc.exe` 崩，`0xc0000374` | `pb` 被当字节缓冲，实为 `SAFEARRAY*`（§6.1）| 事件日志 `Application Error` id=1000 |
| 客户端 `Bad time value` | `RevStatusInfo` 有填充，不是 40 字节（§6.3）| 用 `offsetof` 断言 `sizeof(RevStatusInfo)==40` |
| `mmc.exe` 崩、无提示 | `GetStatus` 返回单个 `BSTR` 而非数组（§7.2）| 在 `uitest info` 里看 `vt` 是否 `0x2008` |
| OCSP 全量 `unauthorized (6)` | 提供程序加载失败，或配置回环不一致（§5.3、§6.2）| 事件日志；提供程序日志里有没有 `Initialize` |
| 事件 `0x8000ffff E_UNEXPECTED`「意外的方法调用顺序」 | 在 `Initialize` 之前调了管理器方法 | 抓调用顺序 |
| `0x800706BA`「RPC 服务器不可用」 | 这是 `certutil` 的错，不是 COM：CA 名少了机器名前缀 | 换成 `机器名\CA名` |
| 状态页显示 0 条但服务正常 | 状态依赖进程内全局（§7.3）| 在 `mmc.exe` 与 `ocspsvc.exe` 分别看 |
| 快照文件存在但 0 行 | 导出/解析问题，不是 COM 问题 | 状态页会直接打印路径、字节数和行数 |

## 9. 怎么自己复现

### 9.1 不注册也能测（推荐）

不需要管理员、不需要写 `HKCR`：`LoadLibrary` + `DllGetClassObject` 直接拿类厂。

```cpp
HMODULE h = LoadLibraryExW(dllPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
auto pfn = (HRESULT (WINAPI*)(REFCLSID, REFIID, void**))GetProcAddress(h, "DllGetClassObject");
IClassFactory *f = nullptr;
pfn(CLSID, IID_IClassFactory, (void**)&f);
IOCSPRevInfoProvider *p = nullptr;
f->CreateInstance(nullptr, IID_IOCSPRevInfoProvider, (void**)&p);
p->Initialize(L"NAS-Monitor-CA", &caCertBlob, &configBlob);   // 配置是 VARIANT，见 §6.2
RevStatusInfo st = {};
CERTTRANSBLOB serial = { n, bytes };                          // 字节反序
p->VerifySerialNumber(&serial, &st);
```

本仓库把这条路径做成了命令行，直接跑就行：

```powershell
# 状态页（同时验证 GetStatus 的返回类型）
.\uitest.exe info -dll .\OcspDbProvider.dll -ca "NAS-Monitor-CA"

# 单条查询
.\uitest.exe verify 6200000003CC4141256F50414D000000000003 -dll .\OcspDbProvider.dll -ca "NAS-Monitor-CA"

# 资源是否齐全（不加载代码，避免半成品 DLL 崩宿主）
.\uitest.exe rescheck -dll .\OcspDbProvider.dll
```

这比"注册 → 重启服务 → 打开 MMC"快一个数量级，而且崩也只崩自己。

### 9.2 用内置提供程序做对照

把 `ProviderCLSID` 临时指向 `{4956D17F-88FD-4198-B287-1E6E65883B19}`，用同样的 harness
调一遍，把 `GetConfigInformation` 返回的二维数组 dump 出来 —— 这是理解属性名和值类型最快的
办法。**记得改回去**，或者事先导出注册表。

### 9.3 端到端验证

```powershell
# 真实 OCSP 请求（需要 CA 证书与序列号）
certutil -verify -urlfetch leaf.cer
# 或
openssl ocsp -issuer ca.cer -serial 0x<serial> -url http://<host>:<port>/ocsp -CAfile ca.cer -no_nonce
```

正确答案要与 CA 库一致：已吊销的返回 `revoked`，且 `reason` 与 `RevokedReason` 相符。

## 10. 没搞清的部分

诚实列出来，免得后来者以为都懂了：

1. **`ftNextPublish` 的精确语义** —— 按"下次刷新时刻"填，未发现反例，但不是强证据。
2. **`Configure` 的 `*pModified`** 在哪些路径上被读 —— 只确认它影响是否落盘。
3. **`Initialize_`（管理器）与 `Initialize`（提供程序）的调用顺序** —— 观察到先提供程序后管理器，
   但无法证明服务永远不会反过来。
4. **多 CA 时管理器是否每 CA 一个实例** —— 现象像是共用一个单例、靠 `caId` 参数区分。
5. **`GetStatus` 的 `pHR` 具体取值** —— 只用过 `S_OK` 和错误码透传，没穷举。
6. **`CERTTRANSBLOB.cb` 在 `0x2011` 之外的变体** —— 只见过 `0x200C` / `0x2011` / `0x0008`。
7. **`ocspsvc.exe` 里那些 `0xD3xxxxx` 消息 ID 的完整含义** —— 只对照了加载失败那几条。

如果你补上了其中任何一条，欢迎开 issue 或 PR —— 这份文档的目的就是让它越来越短。

## 11. 参考

- [REFERENCES.md](REFERENCES.md) —— 官方到底文档化了哪一部分（以及"没有文档"的证据）
- [ARCHITECTURE.md](ARCHITECTURE.md) —— 本实现的结构与配置模型
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) —— OCSP 协议
- [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) —— 轻量级 OCSP 配置
