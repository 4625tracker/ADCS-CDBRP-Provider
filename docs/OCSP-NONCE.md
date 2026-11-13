# OCSP 响应程序与 nonce 扩展

> **中文摘要**：Windows 联机响应程序（Online Responder，`ocspsvc.exe` + `ocspisapi.dll`）
> **不实现 nonce**。带 `id-pkix-ocsp-nonce`（`1.3.6.1.5.5.7.48.1.2`）的请求一律被回
> `OCSPResponseStatus = unauthorized(6)`，响应体只有 5 字节 `30 03 0A 01 06`。
> 这是微软的固定策略，不是本提供程序、也不是某次补丁造成的；本仓库内置的吊销提供程序
> 在进程内只收到序列号，结构上没有能力参与 nonce。测试与部署脚本因此统一加 `-no_nonce`。
> English summary at the end of §1.

## 1. 现象

用 openssl 按默认方式发一个 OCSP 请求（默认带 nonce）：

```bash
openssl ocsp -issuer ca.pem -cert leaf.pem -url http://<responder>:<port>/ocsp \
  -CAfile ca.pem -respout resp.der -reqout req.der
```

得到：

```
req.der   123 字节，扩展 OID 1.3.6.1.5.5.7.48.1.2 位于偏移 0x5C
resp.der    5 字节  30 03 0A 01 06
```

`30 03 0A 01 06` 解出来就是 `OCSPResponse { responseStatus = unauthorized(6) }`——
没有 `responseBytes`，也就是**一个字节的状态信息都没有**。

同一个证书去掉 nonce（`-no_nonce`）立刻正常：1623 字节，`Response verify OK`、
`Cert Status: good`，`This Update` / `Next Update` 相差 `responseseconds`。

| 请求 | 响应 |
|---|---|
| 带 nonce，已知序列号 | 5 字节 `30 03 0A 01 06`（`unauthorized`） |
| 带 nonce，未知序列号 | 5 字节 `30 03 0A 01 06` |
| 不带 nonce，已知序列号 | 1623 字节 `successful` / `good` |
| 不带 nonce，未知序列号 | 1605 字节 `successful` / `unknown` |
| 把 nonce 的 OID 末字节改成未知扩展 `…48.1.10` | 1623 字节 `successful` / `good` |

最后一行是判定"是不是歧视所有扩展"的对照实验：**不是**。响应程序对未知的非关键扩展
照常忽略、照常应答，唯独认得出 nonce 的 OID 并拒绝它。

English summary: the Windows Online Responder rejects any request carrying the
`id-pkix-ocsp-nonce` extension with `unauthorized(6)` (5-byte body `30 03 0A 01 06`).
Unknown extensions are ignored normally, so this is a deliberate nonce policy, not a
parsing limitation.

## 2. 机制：一条策略位，硬编码为"不允许"

`ocspisapi.dll` 的请求处理函数（`GetExtensionVersion` 之后的主路径）里，读完
`requestList`、找到 `requestExtensions` 之后有这么一段逻辑：

```c
// 在 requestExtensions 里找 nonce
ext = find_extension(ctx, "1.3.6.1.5.5.7.48.1.2");
if (ext == NULL) {
    ...正常出响应...
} else if (*(int *)(policy_block + 0x40) == 0) {   // 实测恒为 0（非 0 时会放行）
    status = 6;        // unauthorized
    hr     = 0x80070032;   // ERROR_NOT_SUPPORTED (50)
    // 记一条 0x88609c6 的 trace 后直接返回
} else {
    ...正常出响应...
}
```

- 那个查找函数只是一个 `strcmp("1.3.6.1.5.5.7.48.1.2", extOid)` 的循环，
  OID 字符串常量在镜像里的 ASCII 数据段（`ocspisapi.dll+0x37008` 量级）。
- 策略位看起来来自该模块从响应程序服务拿到的配置块（推断：该指针由响应程序配置对象取回，
  不是本进程里的全局变量）。**全机没有任何配置项对应它**：
  `HKLM\SYSTEM\CurrentControlSet\Services\OCSPSvc` 整棵树递归搜 `*Nonce*` → 0 个值；
  `ocspisapi.dll` / `ocspsvc.exe` 里除那一个 OID 字符串外没有任何 `nonce` 字样，
  也没有 `NoncePolicy` 之类的键名。

这与官方协议文档对得上——[MS-OCSP] §3.2.5 第 8 条：

> The Nonce extension … can be included in requests in the **requestExtensions** field.
> **If the OCSP Extensions responder Nonce Policy is set to "Allowed"**, the responder
> includes the Nonce extension in the **responseExtensions** field of the response.
> **If the Nonce Policy is set to "Not Allowed", the responder rejects the request with
> an "unauthorized" response** as specified in RFC 2560 section 2.3.

而 [MS-OCSPA] §3.2.1.2 的 `ResponderProperties` 表（`AuditFilter`、`ArrayController`、
`ArrayMembers`、`NumOfThreads`、`MaxNumOfCacheEntries`、`LogLevel`、`Debug`、
`EnrollPollInterval`、`RequestFlags`、`MaxIncomingMessageSize`、`NumOfBackendConnections`、
`RefreshRate`、`MaxAge`、`ISAPIDebug`、`MaxNumOfRequestEntries`）里**没有任何 nonce 策略属性**；

`RequestFlags` 这个"控制请求处理方式"的位集合，在公开实现里也只有
`None = 0` / `RejectSignature = 1` 两个成员。

结论：文档承认存在"策略"，但产品没有暴露开关，等价于恒为 `Not Allowed`。

## 3. 这不是本提供程序或某次补丁的问题

三条独立证据：

1. **与提供程序无关**：nonce 请求被拒时，`provider-native.log` 里没有任何
   `VerifySerialNumber` 记录——请求在 ISAPI 层就被挡回去了，根本没到 `OCSPSvc`，
   更没到提供程序。内置 CRL 提供程序同样如此。
2. **与补丁无关**：`ocspisapi.dll` 的 26100.1591（2024 年基线）与 26100.33648（2026-10-28
   更新）两个构建走的是同一分支；实测把系统回滚到 1742 基线（System32 里是 1591 构建）
   之后，带 nonce 的请求照样 5 字节 `unauthorized`。
3. **与响应程序配置无关**：把 `ArrayController` / `ArrayMembers` 改成本机名、
   把 CA 配置改名、甚至停掉 `OCSPSvc`，响应状态都不变。

## 4. 为什么平时不容易发现

| 客户端 | 是否发 nonce | 结果 |
|---|---|---|
| Windows CryptoAPI / `certutil -verify -urlfetch` / .NET | 不发 | 正常 |
| `openssl ocsp`（默认） | 发 | `unauthorized` |
| Firefox（`security.OCSP.require` 相关路径） | 发 | 失败后按软失败策略降级 |
| 浏览器内置的证书状态检查 | 多数不发 | 正常 |

所以"Windows 上一切正常、换 openssl 一测 500/失败"是最典型的表现。

## 5. 正确的用法：加 `-no_nonce`

本仓库所有脚本与文档都按这个约定写：

```bash
# 部署/联调验证
openssl ocsp -issuer ca.cer -serial 0x<serial> -url http://<responder>:<port>/ocsp \
  -CAfile ca.cer -no_nonce
```

```powershell
# Windows 侧端到端
certutil -verify -urlfetch leaf.cer
```

`-no_nonce` 不是"多此一举的开关"：不加它，请求里就会带 nonce，响应程序直接回
`unauthorized`，看起来就像"响应程序挂了"。

## 6. 想真正支持 nonce 需要什么

响应程序自己不会回写 nonce，能改的只有它前面的东西。可选的实现（**本仓库未实现**）：

```
客户端 --nonce--> [ 网关 :8081 ] --去掉nonce--> [ ocspsvc /ocsp ]
                        |
                        +-- 用 CN=...-OCSP-Signer 重签，把 nonce 放回 responseExtensions
```

要点（按 RFC 6960 §4.4.1 与 BasicOCSPResponse 的编码）：

1. 解析 `BasicOCSPRequest`，取出 `requestExtensions` 里的 nonce 值（`extnValue` 是一个
   装着 `OCTET STRING` 的 `OCTET STRING`），删掉该扩展后重新编码请求；
2. 转发给本机 `ocspsvc`（`http://127.0.0.1:<port>/ocsp`）；
3. 若上游返回 `successful`，取出 `responseBytes.response`（`BasicOCSPResponse`），
   把 `tbsResponseData` 里的 `[1] responseExtensions` 保留并追加 nonce 扩展；
   `responderID`、`sigAlg`、`certs` 尽量沿用；
4. 用 OCSP 签名证书（带 `id-kp-OCSPSigning`，本机 `CN=<ca>-OCSP-Signer`）重新签名，
   重新封装 `OCSPResponse`；
5. 上游若不是 `successful`，原样透传（例如 5 字节的 `unauthorized`），不要伪造状态。

代价与风险：

- 网关要持有签名私钥并对外应答——它成了一个真正的 OCSP 响应程序，必须自己保证
  `thisUpdate` / `nextUpdate`、缓存与签名算法的一致性；
- 多一个常驻进程和一份私钥访问权限；
- 任何解析 bug 都直接表现为"证书验证失败"。

如果只是自己用、客户端主要是 Windows 和 `certutil`，**加 `-no_nonce` 就够了**，
值得先确认是否真的需要这条链路。

## 7. 复现步骤

```bash
# 1. 取 CA 证书与一张叶子证书
# 2. 生成带 nonce 的请求（openssl 默认就带）
openssl ocsp -issuer ca.pem -cert leaf.pem -reqout req.der \
  -url http://<responder>:<port>/ocsp -respout resp.der
xxd resp.der          # 期望 30 03 0A 01 06

# 3. 去掉 nonce
openssl ocsp -issuer ca.pem -cert leaf.pem -no_nonce -reqout req0.der \
  -url http://<responder>:<port>/ocsp -respout resp0.der
openssl ocsp -respin resp0.der -issuer ca.pem -cert leaf.pem -CAfile ca.pem
# 期望 Response verify OK
```

## 8. 参考

- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) §2.3、§4.4.1（nonce 与 unauthorized）
- [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) §2.1.1（轻量级 OCSP 的扩展约定）
- [MS-OCSP] §3.2.5 *Processing Events and Sequencing Rules*，第 8 条
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ocsp/a720a740-4b32-4051-9cb6-324390d02602>
- [MS-OCSPA] §3.2.1.2 *ResponderProperties*
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ocspa/c8894946-8439-4285-9515-f575620cc0af>
- [REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md) —— 本仓库对 `ocspisapi.dll` 的其它逆向结论
