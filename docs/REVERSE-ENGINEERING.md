# 逆向笔记：ocsprevp.dll / ocspsvc.exe

> **English abstract.** Notes from reverse engineering the AD CS Online Responder
> (`ocspsvc.exe`, 282624 bytes) and the built-in provider (`ocsprevp.dll`, 217088 bytes) to
> recover the `IOCSPRevInfoProvider` contract. Covers the vtable layout, the `RevStatusInfo`
> structure, the two traps that corrupt the heap or shift every timestamp, and how the
> responder loads a provider. Tools: Ghidra, no symbols (PDB not available).

对象：`C:\Windows\System32\ocsprevp.dll`、`ocspsvc.exe`（无符号，PDB 未加载）。

## 1. 提供程序接口（类型库 + 反汇编双重确认）

```
IOCSPRevInfoProvider        {93F568FF-B8C7-483B-8DEF-5E6EEF8B7650}
   0 Initialize           (BSTR caId, CERTTRANSBLOB* caCert, CERTTRANSBLOB* config)
   1 VerifySerialNumber   (CERTTRANSBLOB* serial, RevStatusInfo* status)
   2 GetConfigInformation (CERTTRANSBLOB* config)
   3 GetProviderManager   (IOCSPRevInfoProviderManager** mgr)

IOCSPRevInfoProviderManager {F85C5127-F108-497D-8FCC-B2A709047C98}
   0 GetProviderInformation(out BSTR name, out BSTR desc)
   1 Configure(hwnd, BSTR caId, blob*, blob*, BOOL* modified, blob* out)
   2 View(hwnd, BSTR caId, blob*, blob*)
   3 GetStatus(BSTR caId, blob*, blob*, VARIANT* status, HRESULT* hr)
   4 Initialize(BSTR caId, blob*, blob* out)
```

两个接口在类型库里都是 `TKIND_DISPATCH`（dual），所以 vtable 在自定义方法之后还有
`GetTypeInfoCount / GetTypeInfo / GetIDsOfNames / Invoke` 四个槽位。本项目的实现把这四个
槽位补齐但返回 `DISP_E_*`，只为对齐布局。

## 2. 类与 vtable（ocsprevp.dll）

| 项 | 地址 |
|---|---|
| coclass `COCSPRevInfoProvider` CLSID | `{4956D17F-88FD-4198-B287-1E6E65883B19}`（rdata 0x180025e50）|
| `CreateInstance` | `0x180003970`（ATL 对象表在 0x18002d000）|
| 构造函数（设置 vtable） | `0x18000261c` → `*this = &PTR_FUN_180023a38` |
| **vtable** | `0x180023a38` |
| QI / AddRef / Release | `0x180004630` / `0x180002f40` / `0x1800054e0` |
| **Initialize** | `0x18000c730` |
| **VerifySerialNumber** | `0x180010c60` |
| GetConfigInformation | `0x18000a9e0` |
| GetProviderManager | `0x18000be00` |

对象构造里还能看到内部类名：`COCSPConfigMgr` / `CCOCSPRevInfoProvider`（宽字符串，`0xa11ca11c` 哨兵）。

## 3. RevStatusInfo 布局与状态码（关键）

`0x180010c60` 的写操作（`param_3` 是 `DWORD*`，按 4 字节步进）：

```
param_3[0]  = 0    // dwStatus = good
param_3[0]  = 1    // dwStatus = revoked
param_3[0]  = 2    // dwStatus = 未在某列表中找到
param_3[9]  = reason           // +36  dwRevocationReason
*(u64*)(param_3+7) = entry+0x10 // +28  ftRevocationDate
*(u64*)(param_3+1) = thisUpdate // +4
*(u64*)(param_3+3) = nextUpdate // +12
*(u64*)(param_3+5) = nextPublish// +20
```

⇒ **偏移 0 / 4 / 12 / 20 / 28 / 36，总长 40 字节（紧密排列，无填充）**。
C# 侧必须 `[StructLayout(LayoutKind.Sequential, Pack = 1)]`、C++ 侧必须 `#pragma pack(1)`，
否则按 8 字节对齐会插 4 字节填充、变 48 字节，时间字段整体错位
（OCSP 里表现为 `This Update: Bad time value`）。

状态码语义：**0 = good，1 = revoked，2 = unknown（列表里没有）**。

## 4. 服务侧如何加载提供程序（ocspsvc.exe）

`FUN_140012eb8`：

```c
if (prop.vt == 8) {                                  // VT_BSTR = ProviderCLSID 字符串
    CLSIDFromString(prop.bstrVal, &clsid);
    hr = CoInitializeEx(NULL, 0);                    // 0 = COINIT_MULTITHREADED
    if (hr < 0) → 失败（记事件 0xD34089B）
    hr = CoCreateInstance(&clsid, NULL, 1 /*INPROC_SERVER*/, &IID_IOCSPRevInfoProvider, &obj+0x58);
    if (hr != 0) → 失败（记事件 0xD3D089B）
}
```

要点：

- **MTA**（`COINIT_MULTITHREADED`），不是 STA —— 提供程序必须线程安全；
- 只用 `CLSCTX_INPROC_SERVER`，所以必须注册 `InprocServer32`（`regsvr32` 即可）；
- 加载失败**只写事件日志**，不抛给 HTTP，上层表现就是所有请求 `unauthorized (6)`。

## 5. 配置 blob 回环（中间那层坑）

`Responder\<CA>\Provider\BaseCrlUrls` 这个子键就是提供程序的配置存储：服务把子键序列化成
blob 传给 `Initialize`，并期望 `GetConfigInformation` 吐回同样的东西。内置实现就是这么配对的。

如果 `Initialize` 忽略传入 blob、`GetConfigInformation` 返回自己拼的字符串 → 回环不一致 →
配置被判无效 → `unauthorized`。改成"存下传入 blob、原样吐回"后，失败从 `unauthorized` 变成
`500`，说明配置这一关过了。

## 6. `GetConfigInformation` 的返回不是字节块，是 VARIANT

`FUN_18000a9e0`（内置 GetConfigInformation）最后调用 `FUN_18001bed8(props, out, ...)`，后者：

```c
local_res20 = (longlong *)param_1[1];
if (local_res20 < 0x10001) {
    local_38.cElements = (ULONG)local_res20;
    ...
    psa = SafeArrayCreate(0xc /* VT_VARIANT */, 2, &local_38);   // 2 维：属性名 / 属性值
    ...
    *param_2 = 0x200C;                  // ← CERTTRANSBLOB.cb 放的是 VARTYPE，不是长度！
    *(SAFEARRAY **)(param_2 + 4) = psa; // ← CERTTRANSBLOB.pb 是 SAFEARRAY*
}
```

即：配置信息是一张 **属性表（`VT_ARRAY | VT_VARIANT` 的 SAFEARRAY）**，`CERTTRANSBLOB`
只被当作一个 `{VARTYPE, pointer}` 的载体。

用字节缓冲去接/去返回它 → 服务按变体数组释放 → 堆损坏 → `ocspsvc.exe` 崩溃
（`Application Error` id=1000，`0xc0000374` STATUS_HEAP_CORRUPTION）。

同理 `Configure` / `View` 收到的 "config" 实参也是变体：`cb` 是 VARTYPE
（`0x200C` = `VT_ARRAY|VT_VARIANT`，`0x2011` = `VT_ARRAY|VT_UI1`），`pb` 是 `SAFEARRAY*`。

## 7. `GetStatus` 必须返回 `string[]`

反编译 `Microsoft.CertificateAuthority.OcspSnapin.dll`（托管）与 `OCSPAdminNative.dll`
（native 中间层）后定位：

```csharp
// RevProvMgr.RevProvGetStatus（托管侧）
DllRevProvGetStatus(...);
status = (String[])obj;          // ← castclass String[]
```

```c
// OCSPAdminNative!DllRevProvGetStatus（native 侧）
SAFEARRAY *sa = SafeArrayCreate(VT_UI1, 1, &bound);   // 配置按 VT_ARRAY|VT_UI1(0x2011) 传入
mgr = GetManager(providerClsid);                       // CoCreate + vtable[0x30]=GetProviderManager
mgr->vtable[0x30](mgr, caId, &v, pStatus, pHR);        // 0x30 = GetStatus
```

也就是说 `pStatus` 必须是 **`VT_ARRAY | VT_BSTR`（BSTR 数组）**。返回单个 `VT_BSTR` 时，
托管侧 `castclass String[]` 抛 `InvalidCastException`；而
`OCSPError::IsExceptionUnRecoverable` 把非白名单异常判为**不可恢复**并 `throw` 重抛
（见 `ShowExceptionError` 的 IL），于是 `mmc.exe` 直接退出。

改成 BSTR 数组后：`mmc alive=True responding=True crashes=0`。

另外一个坑：`SnapInNode._OnActionWrapper` 里只要抛异常，snapin 自己的报错对话框
（`OCSPErrorImpl.ShowExceptionError`）也会抛异常，真实错误信息被吞掉、只剩 MMC 崩溃。
排查这类问题不要依赖 MMC 的报错。

## 8. 序列号是**字节反序**传进来的

抓到的实参：`cb=19, bytes = 03 00 00 00 00 00 4D 41 50 6F 25 41 41 CC 03 00 …`，
而库里该证书的序列号是 `62 00 00 00 03 CC 41 41 25 6F 50 41 4D 00 00 00 00 00 03`。
按**字节**反转即完全吻合（等价于小端存放），所以匹配时要把 blob 字节反转后再查表。

注意是反转**字节**，不是反转十六进制字符串——两者在奇数长度的序列号上结果不同。

## 9. 最终形态

本仓库的原生实现（`src/native/OcspDbProvider.cpp`）：

- CLSID `{7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9}`，`ThreadingModel=Both`，`regsvr32` 注册；
- `IOCSPRevInfoProvider` 四个方法 + 最小 manager（含 dual 的 IDispatch 槽位）；
- 数据源 = 每个 CA 一份 `revdb.dat` 快照（计划任务每分钟刷新），内存缓存按 mtime 重载；
- 状态码 0/1/2 与时间字段按 §3 的布局填写，`dwRevocationReason` / `ftRevocationDate` 从快照取；
- 配置按 `[ca:<ca-id>]` 分段，支持多 CA 各自的状态码映射。

实测（openssl，`-CAfile` 验签通过）：有效 → `good`；已吊销 → `revoked`，reason 与时间与 CA 库一致；
随机序列号 → 按配置的 `unknownstatus` 回答，服务无崩溃。
