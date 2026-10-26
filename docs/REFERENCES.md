# 关于「写一个联机响应程序吊销提供程序」的官方资料

结论先说：**微软没有公开这个接口的参考文档。** 下面这些是能查到的、并且我逐个验证过的。
其余一切（vtable 顺序、结构体布局、语义）都只能靠逆向和试错 —— 见
[REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md)。

## 1. 证据：它确实没有文档

这些检查都可以自己复现。

| 检查 | 结果 |
|---|---|
| Windows SDK 10.0.26100 里找 `*ocsp*` 头文件 | **零个**（`Get-ChildItem -Recurse -Filter *ocsp*` 无命中） |
| 在整个 SDK 的 `*.h` 里全文搜 `IOCSPRevInfoProvider` | **零命中** |
| learn.microsoft.com 搜 `IOCSPRevInfoProviderManager` | **0 条**（[搜索 API](https://learn.microsoft.com/api/search?search=IOCSPRevInfoProviderManager&locale=en-us)） |
| learn.microsoft.com 搜 `RevStatusInfo` | **0 条** |
| learn.microsoft.com 搜 `IOCSPRevInfoProvider` | 2 条，都是 `ProviderCLSID` 属性页，只在正文里顺带提了一句 |

`ProviderCLSID` 那页的原话（这是全站唯一一处提到接口名的地方）：

> "A provider implements **IOCSPRevInfoProvider** interface and processes certificate status
> requests for a responder service."
>
> —— [IOCSPCAConfiguration::get_ProviderCLSID (certadm.h)](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_providerclsid)

也就是说：微软承认这个接口存在、承认它叫这个名字，但**没有给出任何定义**。

## 2. 真正有用的四份官方资料

### 2.1 配置数据的形状 —— `IOCSPCAConfiguration::ProviderProperties`

<https://learn.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_providerproperties>

这页是**最有用的一份**，因为它解释了配置块为什么是那个奇怪形状：

> "The **VARIANT** returned in *pVal* is a pointer to a safe array that contains the properties
> as name-value pairs. This array is a two-dimensional array of elements, each of type VARIANT.
> The array contains one row for each named property in the collection. Each row contains two
> columns: the property name and the property value."

并且列出了**内置提供程序（ocsprevp.dll）的属性名**：

| 属性 | 类型 |
|---|---|
| `BaseCrl` | REG_BINARY |
| `BaseCrlUrls` | REG_MULTI_SZ |
| `CrlUrlTimeout` | DWORD |
| `DeltaCrl` | REG_BINARY |
| `DeltaCrlUrls` | REG_MULTI_SZ |
| `RefreshTimeOut` | DWORD |
| `RevocationErrorCode` | DWORD |
| `IssuedSerialNumbersDirectories` | REG_MULTI_SZ |

**这就是为什么**提供程序在 `GetConfigInformation` / `Initialize` 里收到的是一个
「二维 VARIANT 名值对数组」，而它又被塞进 `CERTTRANSBLOB` 传过来：
管理侧把它当 `VARIANT*` 存在 CA 配置里，运行侧用同一个 VARIANT 传给你。
搞清楚这一点之前，往 `CERTTRANSBLOB.pb` 里塞字节缓冲会直接把 `ocspsvc.exe` 的堆写坏。

### 2.2 `CERTTRANSBLOB` 的定义

<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/a94fb0b1-902f-43ea-9422-f2d24bcb10b6>

```c
typedef struct _CERTTRANSBLOB {
  ULONG cb;
  [size_is(cb), unique] BYTE* pb;
} CERTTRANSBLOB;
```

文档明确写了 `pb` 里可以装的内容包括「CA properties」以及按 [MS-WCCE] 2.2.2 规则
marshal 的 `VARIANT` —— 也就是说，`cb` 在这里往往**不是字节数**，而是 VARTYPE
（例如 `0x200C` = `VT_VARIANT|VT_ARRAY`）。这一点文档没有直说，但两条放在一起就清楚了。

### 2.3 管理侧接口（怎么把提供程序配上）

- [IOCSPAdmin](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-iocspadmin) —— 管理整个响应程序服务器
- [IOCSPCAConfiguration](https://learn.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-iocspcaconfiguration) —— 单个 CA 的配置：`ProviderCLSID`、`ProviderProperties`、`LocalRevocationInformation` 等
- 头文件：`certadm.h`（`#include <Certserv.h>`），库 `Certadm.lib`，DLL `Certadm.dll`
- 最低支持：Windows Server 2008 Datacenter / Enterprise

这一侧是**完整文档化**的，用它可以把 `ProviderCLSID` 指向自己的 COM 组件、把
`ProviderProperties` 写进去，不需要碰注册表。

### 2.4 产品运维文档

2008 R2 时代的部署/配置文档（只有运维向，没有 SDK 内容）：
<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc731099(v=ws.10)>

## 3. 缺的那部分

官方文档没有覆盖、只能靠逆向的，至少包括：

- `IOCSPRevInfoProvider` 的 **vtable 顺序**（含 dual 接口的 IDispatch 槽位）
- `IOCSPRevInfoProviderManager` 的 `GetStatus` 返回 **`VT_ARRAY | VT_BSTR`**，不是单个 BSTR
- `RevStatusInfo` 是 **40 字节紧凑结构**，无对齐填充
- 传进来的序列号是**字节反序**的
- `Initialize` 的 CA id 是**裸 CA 名**，而 `Configure`/配置串需要**主机名前缀**
- `GetProviderManager` 拿到的是单例，`Configure`/`View` 的 `pModified` 语义
- 全部失败路径都只写事件日志，不通过 COM 返回

这些的验证方法都写在 [REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md) 里，可以照着复现。

## 4. 写文章时怎么引用

如果要在文章里说明「为什么这些东西是逆向出来的」，建议这样写：

> 这个接口没有公开文档。Windows SDK 里没有任何 OCSP 相关头文件，微软文档站搜
> `IOCSPRevInfoProviderManager` 和 `RevStatusInfo` 都是零结果；唯一提到接口名的，是
> `IOCSPCAConfiguration::ProviderCLSID` 属性页里的一句"A provider implements
> IOCSPRevInfoProvider interface"。
>
> 能查到的只有它的**输入端**：`ProviderProperties` 文档说明了配置是一份二维 VARIANT
> 名值对，并给出了内置提供程序的属性名；`CERTTRANSBLOB` 的协议定义说明了外层容器。
> 至于这个容器怎么交付给提供程序、结构体怎么排布、序列号怎么编码 —— 一个字都没有。

这段话是可以逐条点开验证的，比"文档不全"这种笼统说法有力得多。
