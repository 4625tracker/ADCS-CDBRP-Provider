// OcspDbProvider.cpp —— AD CS 联机响应程序的自定义吊销提供程序（原生 COM，数据源 = CA 数据库快照）
//
// 契约来自对 ocsprevp.dll / ocspsvc.exe 的逆向（见 ../../docs/REVERSE-ENGINEERING.md）：
//   IOCSPRevInfoProvider {93F568FF-B8C7-483B-8DEF-5E6EEF8B7650}
//     Initialize / VerifySerialNumber / GetConfigInformation / GetProviderManager
//   RevStatusInfo: dwStatus(0) ftThisUpdate(4) ftNextUpdate(12) ftNextPublish(20)
//                  ftRevocationDate(28) dwRevocationReason(36)  —— 40 字节，紧密排列
//   dwStatus: 0 = good, 1 = revoked, 2 = unknown
//
// 可移植性约定（开源版新增）：
//   * 安装目录不再写死：环境变量 OCSPDBPROVIDER_DIR -> HKLM\SOFTWARE\OcspDbProvider\InstallDir
//     -> %ProgramData%\OcspDbProvider，逐级回退；
//   * 多 CA：每个 CA 有独立快照与状态码映射，配置按 [ca:<ca-id>] 分段；
//   * 双语界面：跟随系统 UI 语言，可用 OCSPDBPROVIDER_LANG=zh|en 强制；
//   * 最低 Windows 7 / Server 2008 R2（_WIN32_WINNT = 0x0601）。
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <commdlg.h>
#include <stddef.h>
#include <stdio.h>
#include <string>
#include <map>
#include <vector>
#include "resource.h"
#include "OcspDbConfig.h"

// ------------------------------------------------------------------ 常量

static const CLSID CLSID_OcspDbProvider =
    {0x7b0c4b1e, 0x93a1, 0x4c0f, {0x9e, 0x52, 0x0d, 0x2a, 0x6a, 0x5b, 0x41, 0xc9}};

static const IID IID_IOCSPRevInfoProvider =
    {0x93f568ff, 0xb8c7, 0x483b, {0x8d, 0xef, 0x5e, 0x6e, 0xef, 0x8b, 0x76, 0x50}};

static const IID IID_IOCSPRevInfoProviderManager =
    {0xf85c5127, 0xf108, 0x497d, {0x8f, 0xcc, 0xb2, 0xa7, 0x09, 0x04, 0x7c, 0x98}};

#define PROVIDER_PROGID L"OcspDb.RevInfoProvider.1"
#define LEGACY_PROGID   L"NasOcsp.DbRevInfoProvider.1"   // 老版本 ProgID，卸载时一并清理
#define REG_ROOT        L"SOFTWARE\\OcspDbProvider"

// ------------------------------------------------------------------ 结构 / 接口

struct CERTTRANSBLOB { ULONG cb; PBYTE pb; };

#pragma pack(push, 1)
struct RevStatusInfo {
    DWORD    dwStatus;
    FILETIME ftThisUpdate;
    FILETIME ftNextUpdate;
    FILETIME ftNextPublish;
    FILETIME ftRevocationDate;
    DWORD    dwRevocationReason;
};
#pragma pack(pop)

// 布局一旦漂移，客户端看到的是 "Bad time value"，而代码一行都没错。用编译期断言钉死。
static_assert(sizeof(RevStatusInfo) == 40, "RevStatusInfo must stay 40 bytes (packed)");
static_assert(offsetof(RevStatusInfo, ftThisUpdate)       == 4,  "layout drift: ftThisUpdate");
static_assert(offsetof(RevStatusInfo, ftNextUpdate)       == 12, "layout drift: ftNextUpdate");
static_assert(offsetof(RevStatusInfo, ftNextPublish)      == 20, "layout drift: ftNextPublish");
static_assert(offsetof(RevStatusInfo, ftRevocationDate)   == 28, "layout drift: ftRevocationDate");
static_assert(offsetof(RevStatusInfo, dwRevocationReason) == 36, "layout drift: dwRevocationReason");

struct IOCSPRevInfoProvider : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Initialize(BSTR bstrCAId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pConfig) = 0;
    virtual HRESULT STDMETHODCALLTYPE VerifySerialNumber(CERTTRANSBLOB *pSerial, RevStatusInfo *pStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetConfigInformation(CERTTRANSBLOB *pConfig) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProviderManager(IUnknown **ppMgr) = 0;
    // dual 接口的 IDispatch 槽位（typelib 里是 TKIND_DISPATCH，槽位排在自定义方法之后）
    virtual HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *pc) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT i, LCID l, ITypeInfo **p) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) = 0;
    virtual HRESULT STDMETHODCALLTYPE Invoke(DISPID d, REFIID r, LCID l, WORD w, DISPPARAMS *p, VARIANT *v, EXCEPINFO *e, UINT *a) = 0;
};

struct IOCSPRevInfoProviderManager : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetProviderInformation(BSTR *pName, BSTR *pDesc) = 0;
    virtual HRESULT STDMETHODCALLTYPE Configure(HWND hwnd, BSTR caId, CERTTRANSBLOB *pCACert,
                                                CERTTRANSBLOB *pIn, BOOL *pModified, CERTTRANSBLOB *pOut) = 0;
    virtual HRESULT STDMETHODCALLTYPE View(HWND hwnd, BSTR caId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pIn) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStatus(BSTR caId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pIn,
                                                VARIANT *pStatus, HRESULT *pHR) = 0;
    virtual HRESULT STDMETHODCALLTYPE Initialize_(BSTR caId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pOut) = 0;
    // dual 接口的 IDispatch 槽位
    virtual HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *pc) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT i, LCID l, ITypeInfo **p) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) = 0;
    virtual HRESULT STDMETHODCALLTYPE Invoke(DISPID d, REFIID r, LCID l, WORD w, DISPPARAMS *p, VARIANT *v, EXCEPINFO *e, UINT *a) = 0;
};

// ------------------------------------------------------------------ 路径 / 语言
//
// 安装目录、provider.ini 与每个 CA 的生效配置由 OcspDbConfig 提供，和 OcspConfig.exe
// 共用同一份实现，避免两个程序对配置格式产生分歧。

static std::wstring CaptureDir()
{
    wchar_t buf[MAX_PATH * 2] = {0};
    if (GetEnvironmentVariableW(L"OCSPDBPROVIDER_CAPTURE_DIR", buf, _countof(buf)) > 0)
        return TrimTrailingSlash(buf);
    return InstallDir();
}

static std::wstring LogPath() { return JoinPath(InstallDir(), L"provider-native.log"); }

// ------------------------------------------------------------------ 小工具

static std::wstring g_dllPath;
static HINSTANCE g_hInst = NULL;
static CRITICAL_SECTION g_cs;
static bool g_csInit = false;
static CRITICAL_SECTION g_dbCs;
static bool g_dbCsInit = false;

// 供配置界面显示的统计
static volatile LONG  g_queryCount = 0;      // VerifySerialNumber 调用次数

static void LogLine(const wchar_t *fmt, ...)
{
    if (!g_csInit) return;
    wchar_t msg[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(msg, _countof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[1200];
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"%04u-%02u-%02u %02u:%02u:%02u [pid %lu]  %s\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId(), msg);

    EnterCriticalSection(&g_cs);
    std::wstring file = LogPath();
    HANDLE h = CreateFileW(file.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        int len = (int)wcslen(line);
        // UTF-8 输出，方便看
        char utf8[2400];
        int n = WideCharToMultiByte(CP_UTF8, 0, line, len, utf8, sizeof(utf8), NULL, NULL);
        if (n > 0) WriteFile(h, utf8, (DWORD)n, &written, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_cs);
}

static void LogQI(const wchar_t *who, REFIID riid, HRESULT hr)
{
    wchar_t g[64] = L"";
    StringFromGUID2(riid, g, 64);
    LogLine(L"[qi] %s -> %s  hr=0x%08X", who, g, (unsigned)hr);
}

static LONG64 FileTimeNow(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    LONG64 v = (LONG64)u.QuadPart;
    return v - (v % 10000000LL);       // 取整到秒（FILETIME 单位 100ns）
}

static FILETIME FileTimeFromNowMinutes(int minutes)
{
    LONG64 v = FileTimeNow() + (LONG64)minutes * 60LL * 10000000LL;
    FILETIME ft;
    ULARGE_INTEGER u;
    u.QuadPart = (ULONGLONG)v;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    return ft;
}

static FILETIME FileTimeFromLongLong(LONG64 v)
{
    FILETIME ft = {0, 0};
    if (v > 0) {
        ULARGE_INTEGER u;
        u.QuadPart = (ULONGLONG)v;
        ft.dwLowDateTime = u.LowPart;
        ft.dwHighDateTime = u.HighPart;
    }
    return ft;
}

static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 统一成大写十六进制、剥掉前导零（至少保留一位）。
// 注意：早期版本这里对数字也做了 c-32，'0'..'9' 会变成控制字符——虽然两边一致时
// 仍能碰巧匹配，但前导零无法归一，属于隐患，已修正。
static void NormalizeSerial(const std::string &hex, std::string &out)
{
    out.clear();
    for (char c : hex) {
        int v = HexNibble(c);
        if (v < 0) continue;
        out.push_back((char)(v < 10 ? ('0' + v) : ('A' + v - 10)));
    }
    size_t i = 0;
    while (i + 1 < out.size() && out[i] == '0') i++;
    out = out.substr(i);
    if (out.empty()) out = "0";
}

// 联机响应程序传进来的序列号是【字节反序】的（等价于小端），这里同时给出两种形式
static void SerialForms(const CERTTRANSBLOB *p, std::string &fwd, std::string &rev)
{
    fwd.clear();
    rev.clear();
    if (!p || !p->pb || p->cb == 0) { fwd = "0"; rev = "0"; return; }
    char buf[3];
    for (ULONG i = 0; i < p->cb; i++) {
        sprintf_s(buf, "%02X", p->pb[i]);
        fwd += buf;
    }
    for (ULONG i = p->cb; i > 0; i--) {
        sprintf_s(buf, "%02X", p->pb[i - 1]);
        rev += buf;
    }
    std::string a, b;
    NormalizeSerial(fwd, a);
    NormalizeSerial(rev, b);
    fwd = a;
    rev = b;
}

// ------------------------------------------------------------------ 配置模型
//
// CaConfig / Settings 以及 provider.ini 的读写实现在 OcspDbConfig.cpp，
// 与独立配置工具 OcspConfig.exe 共用，保证两边对配置格式的理解一致。

// ------------------------------------------------------------------ 快照

struct RevEntry {
    int      disposition;
    LONG64   revokedWhen;   // FILETIME (0 = 未吊销)
    int      reason;
    LONG64   notAfter;
};

// 每个 CA 一份快照缓存；统一由 g_dbCs 保护（查询是内存查表，锁竞争可以忽略）
class RevDb
{
public:
    explicit RevDb(const std::wstring &caId) : m_caId(caId), m_fileStamp(0), m_loadedTick(0) {
        m_lastReloadText[0] = 0;
    }

    // 强制重读快照（配置界面的「立即重载」按钮、Initialize 用）
    void Reload()
    {
        EnterCriticalSection(&g_dbCs);
        m_fileStamp = 0;
        m_loadedTick = 0;
        EnsureFresh();
        LeaveCriticalSection(&g_dbCs);
    }

    // 联机响应程序传进来的序列号字节顺序并不总是 big-endian（实测可能是反序，
    // 或者带额外填充），所以这里做容错匹配：先精确、再正序/反序子串，且必须唯一命中。
    bool Lookup(const std::string &serial, RevEntry &entry, Settings &st)
    {
        EnterCriticalSection(&g_dbCs);
        EnsureFresh();
        st = m_st;
        bool found = false;

        std::map<std::string, RevEntry>::const_iterator it = m_map.find(serial);
        if (it != m_map.end()) { entry = it->second; found = true; }
        std::string rev(serial.rbegin(), serial.rend());
        if (!found) {
            it = m_map.find(rev);
            if (it != m_map.end()) { entry = it->second; found = true; }
        }
        if (!found) {
            const RevEntry *hit = NULL;
            int hits = 0;
            for (std::map<std::string, RevEntry>::const_iterator kv = m_map.begin(); kv != m_map.end(); ++kv) {
                const std::string &k = kv->first;
                if (k.size() < 8) continue;
                if (serial.find(k) != std::string::npos || rev.find(k) != std::string::npos) {
                    hit = &kv->second;
                    if (++hits > 1) break;
                }
            }
            if (hits == 1 && hit) { entry = *hit; found = true; }
        }
        LeaveCriticalSection(&g_dbCs);
        return found;
    }

    size_t Count()
    {
        EnterCriticalSection(&g_dbCs);
        EnsureFresh();
        size_t n = m_map.size();
        LeaveCriticalSection(&g_dbCs);
        return n;
    }

    void SnapshotPath(std::wstring &path, Settings &st)
    {
        EnterCriticalSection(&g_dbCs);
        EnsureFresh();
        path = m_snapPath;
        st = m_st;
        LeaveCriticalSection(&g_dbCs);
    }

    std::wstring LoadedAt()
    {
        EnterCriticalSection(&g_dbCs);
        std::wstring t = m_lastReloadText[0] ? m_lastReloadText : Tr(L"（尚未加载）", L"(not loaded yet)");
        LeaveCriticalSection(&g_dbCs);
        return t;
    }

    const std::wstring &CaId() const { return m_caId; }

private:
    // 调用方必须持有 g_dbCs
    void EnsureFresh()
    {
        Settings st = ConfigEffectiveFor(m_caId);
        // 配置里的快照路径变了 -> 立刻重载
        if (st.snapshot != m_snapPath) {
            m_snapPath = st.snapshot;
            m_fileStamp = 0;
            m_loadedTick = 0;
        }
        m_st = st;

        DWORD now = GetTickCount();
        DWORD interval = (DWORD)((st.checkSeconds > 0 ? st.checkSeconds : 1) * 1000);
        if (m_loadedTick != 0 && (now - m_loadedTick) < interval) return;   // 缓存有效期内不重复看文件
        m_loadedTick = now;

        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExW(m_snapPath.c_str(), GetFileExInfoStandard, &fad)) {
            if (!m_map.empty()) { m_map.clear(); m_fileStamp = 0; }
            return;
        }
        LONG64 stamp = ((LONG64)fad.ftLastWriteTime.dwHighDateTime << 32) | fad.ftLastWriteTime.dwLowDateTime;
        if (stamp == m_fileStamp && !m_map.empty()) return;

        std::string text = ReadTextFileUtf8(m_snapPath);
        if (text.empty()) {
            LogLine(L"snapshot open failed or empty: %s (err=%lu)", m_snapPath.c_str(), GetLastError());
            return;
        }

        std::map<std::string, RevEntry> fresh;
        size_t pos = 0;
        while (pos < text.size()) {
            size_t nl = text.find('\n', pos);
            if (nl == std::string::npos) nl = text.size();
            std::string line = text.substr(pos, nl - pos);
            pos = nl + 1;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (line.empty() || line[0] == '#') continue;

            // serial \t disposition \t revokedWhen \t reason \t notAfter
            std::vector<std::string> f;
            size_t s = 0;
            while (true) {
                size_t t = line.find('\t', s);
                if (t == std::string::npos) { f.push_back(line.substr(s)); break; }
                f.push_back(line.substr(s, t - s));
                s = t + 1;
            }
            if (f.size() < 3) continue;
            RevEntry e;
            e.disposition = atoi(f[1].c_str());
            e.revokedWhen = (f.size() > 2) ? _strtoi64(f[2].c_str(), NULL, 10) : 0;
            e.reason      = (f.size() > 3) ? atoi(f[3].c_str()) : 0;
            e.notAfter    = (f.size() > 4) ? _strtoi64(f[4].c_str(), NULL, 10) : 0;
            std::string norm;
            NormalizeSerial(f[0], norm);
            fresh[norm] = e;
        }
        if (!fresh.empty()) {
            m_map.swap(fresh);
            m_fileStamp = stamp;
            SYSTEMTIME tt;
            GetLocalTime(&tt);
            _snwprintf_s(m_lastReloadText, _countof(m_lastReloadText), _TRUNCATE,
                         L"%04u-%02u-%02u %02u:%02u:%02u", tt.wYear, tt.wMonth, tt.wDay,
                         tt.wHour, tt.wMinute, tt.wSecond);
            LogLine(L"snapshot reloaded (%s): %Iu entries", m_caId.c_str(), m_map.size());
        }
    }

    std::wstring m_caId;
    std::wstring m_snapPath;
    Settings     m_st;
    std::map<std::string, RevEntry> m_map;
    LONG64       m_fileStamp;
    DWORD        m_loadedTick;
    wchar_t      m_lastReloadText[64];
};

static std::map<std::wstring, RevDb *> g_dbs;

static RevDb &DbForCA(const std::wstring &caId)
{
    EnterCriticalSection(&g_dbCs);
    std::map<std::wstring, RevDb *>::iterator it = g_dbs.find(caId);
    if (it != g_dbs.end()) {
        RevDb *db = it->second;
        LeaveCriticalSection(&g_dbCs);
        return *db;
    }
    LeaveCriticalSection(&g_dbCs);

    RevDb *db = new (std::nothrow) RevDb(caId);
    if (!db) {
        static RevDb fallback(L"");
        return fallback;
    }
    EnterCriticalSection(&g_dbCs);
    std::pair<std::map<std::wstring, RevDb *>::iterator, bool> ins = g_dbs.insert(std::make_pair(caId, db));
    RevDb *result = ins.first->second;
    LeaveCriticalSection(&g_dbCs);
    if (result != db) { delete db; }
    return *result;
}

// ------------------------------------------------------------------ 提供程序

// 单例 manager（provider 的 QI 和 GetProviderManager 都返回它）
IUnknown *GetSharedManager();

class CRevInfoProvider : public IOCSPRevInfoProvider
{
public:
    CRevInfoProvider() : m_ref(1) { VariantInit(&m_cfgVar); InterlockedIncrement(&g_objects); }
    ~CRevInfoProvider() { VariantClear(&m_cfgVar); InterlockedDecrement(&g_objects); }

    static LONG g_objects;

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IOCSPRevInfoProvider)) {
            *ppv = static_cast<IOCSPRevInfoProvider *>(this);
            AddRef();
            LogQI(L"provider", riid, S_OK);
            return S_OK;
        }
        // 托管 snapin（Microsoft.CertificateAuthority.OcspSnapin）会把 provider 对象
        // 直接强转成 IOCSPRevInfoProviderManager；这里不给就会抛 InvalidCastException
        // 并把 mmc.exe 带崩（E_NOINTERFACE）。
        if (IsEqualIID(riid, IID_IOCSPRevInfoProviderManager)) {
            *ppv = GetSharedManager();          // 已 AddRef
            LogQI(L"provider->mgr", riid, *ppv ? S_OK : E_OUTOFMEMORY);
            return *ppv ? S_OK : E_OUTOFMEMORY;
        }
        LogQI(L"provider", riid, E_NOINTERFACE);
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef()  { return (ULONG)InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release()
    {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }

    // IOCSPRevInfoProvider
    STDMETHODIMP Initialize(BSTR bstrCAId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pConfig)
    {
        UNREFERENCED_PARAMETER(pCACert);
        if (bstrCAId) m_caId = bstrCAId;
        else m_caId.clear();

        // 配置回环：服务把持久化的 VARIANT 传进来，并期望 GetConfigInformation 原样吐回。
        if (pConfig && pConfig->pb && pConfig->cb == 0x200C) {
            VARIANT src;
            VariantInit(&src);
            src.vt = 0x200C;
            src.parray = (SAFEARRAY *)pConfig->pb;
            VariantClear(&m_cfgVar);
            if (FAILED(VariantCopy(&m_cfgVar, &src))) {
                LogLine(L"Initialize: VariantCopy failed");
            }
        }
        RevDb &db = DbForCA(m_caId);
        db.Reload();                        // 让配置界面/状态页一打开就有真实行数与加载时间

        {
            UINT dims = 0;
            if (m_cfgVar.vt == 0x200C && m_cfgVar.parray) dims = SafeArrayGetDim(m_cfgVar.parray);
            LogLine(L"Initialize: incoming cfg vt=0x%04X cached vt=0x%04X dims=%u",
                    pConfig ? (unsigned)pConfig->cb : 0, (unsigned)m_cfgVar.vt, dims);
        }
        LogLine(L"Initialize ca=%s cfgType=0x%04X entries=%Iu",
                m_caId.empty() ? L"(null)" : m_caId.c_str(),
                pConfig ? (unsigned)pConfig->cb : 0, db.Count());
        return S_OK;
    }

    STDMETHODIMP VerifySerialNumber(CERTTRANSBLOB *pSerial, RevStatusInfo *pStatus)
    {
        if (!pStatus) return E_POINTER;
        ZeroMemory(pStatus, sizeof(*pStatus));
        pStatus->ftThisUpdate  = FileTimeFromLongLong(FileTimeNow());
        pStatus->ftNextUpdate  = FileTimeFromNowMinutes(30);
        pStatus->ftNextPublish = FileTimeFromNowMinutes(120);

        LONG n = InterlockedIncrement(&m_calls);
        InterlockedIncrement(&g_queryCount);
        if (n <= 6) {
            char raw[64] = {0};
            int off = 0;
            if (pSerial && pSerial->pb) {
                ULONG cnt = pSerial->cb;
                if (cnt > 16) cnt = 16;
                for (ULONG i = 0; i < cnt && off < 60; i++)
                    off += sprintf_s(raw + off, sizeof(raw) - off, "%02X ", pSerial->pb[i]);
            }
            std::string f2, r2;
            SerialForms(pSerial, f2, r2);
            LogLine(L"VerifySerialNumber #%ld cb=%lu bytes=[%S] fwd=%S rev=%S",
                    n, pSerial ? pSerial->cb : 0, raw, f2.c_str(), r2.c_str());
        }
        std::string serial, serialRev;
        SerialForms(pSerial, serial, serialRev);
        RevEntry e;
        Settings st;
        RevDb &db = DbForCA(m_caId);
        bool hit = db.Lookup(serial, e, st);
        if (!hit) hit = db.Lookup(serialRev, e, st);
        if (!hit) {
            pStatus->dwStatus = (DWORD)st.unknownStatus;
            static LONG s_logged = 0;
            if (InterlockedIncrement(&s_logged) <= 5)
                LogLine(L"serial %S not in snapshot (%s) -> status %d",
                        serial.c_str(), m_caId.c_str(), (int)pStatus->dwStatus);
            return S_OK;
        }
        if (e.disposition == 21) {
            pStatus->dwStatus = (DWORD)st.revokedStatus;
            pStatus->dwRevocationReason = (DWORD)e.reason;
            pStatus->ftRevocationDate = FileTimeFromLongLong(e.revokedWhen > 0 ? e.revokedWhen : FileTimeNow());
        } else if (e.disposition == 20 || e.disposition == 15 || e.disposition == 14) {
            pStatus->dwStatus = (DWORD)st.validStatus;
        } else {
            pStatus->dwStatus = (DWORD)st.unknownStatus;
        }
        return S_OK;
    }

    STDMETHODIMP GetConfigInformation(CERTTRANSBLOB *pConfig)
    {
        if (!pConfig) return E_POINTER;
        pConfig->cb = 0;
        pConfig->pb = NULL;

        // 空配置：返回一个空的属性表（合法的 VT_ARRAY|VT_VARIANT，0 行）
        VARIANT out;
        VariantInit(&out);
        if (m_cfgVar.vt == 0x200C && m_cfgVar.parray) {
            if (FAILED(VariantCopy(&out, &m_cfgVar))) return E_OUTOFMEMORY;
        } else {
            // 内置实现的形状是「2 维：N 行 × 2 列（属性名 / 属性值）」；
            // 托管 snapin 会把它转成 object[,]，给 1 维数组会抛 InvalidCastException。
            SAFEARRAYBOUND bounds[2];
            bounds[0].lLbound = 0; bounds[0].cElements = 0;
            bounds[1].lLbound = 0; bounds[1].cElements = 2;
            out.vt = 0x200C;
            out.parray = SafeArrayCreate(VT_VARIANT, 2, bounds);
            if (!out.parray) return E_OUTOFMEMORY;
        }
        LogLine(L"GetConfigInformation -> vt=0x%04X dims=%u", (unsigned)out.vt,
                out.parray ? SafeArrayGetDim(out.parray) : 0);
        pConfig->cb = (ULONG)out.vt;          // 注意：这里放的是 VARTYPE，不是长度
        pConfig->pb = (PBYTE)out.parray;      // 所有权交给调用方（由它 SafeArrayDestroy）
        out.parray = NULL;
        return S_OK;
    }

    STDMETHODIMP GetProviderManager(IUnknown **ppMgr)
    {
        LogLine(L"GetProviderManager called");
        if (!ppMgr) return E_POINTER;
        *ppMgr = GetSharedManager();       // 已 AddRef
        return *ppMgr ? S_OK : E_OUTOFMEMORY;
    }

    // ---- dual 接口的 IDispatch 槽位 ----
    STDMETHODIMP GetTypeInfoCount(UINT *pc)
    {
        LogLine(L"[disp] provider.GetTypeInfoCount");
        if (pc) *pc = 0;
        return S_OK;
    }
    STDMETHODIMP GetTypeInfo(UINT, LCID, ITypeInfo **pp)
    {
        LogLine(L"[disp] provider.GetTypeInfo");
        if (pp) *pp = NULL;
        return E_NOTIMPL;
    }
    STDMETHODIMP GetIDsOfNames(REFIID, LPOLESTR *names, UINT c, LCID, DISPID *ids)
    {
        LogLine(L"[disp] provider.GetIDsOfNames count=%u name0=%s", c, (c && names) ? names[0] : L"");
        return DISP_E_UNKNOWNNAME;
    }
    STDMETHODIMP Invoke(DISPID id, REFIID, LCID, WORD flags, DISPPARAMS *pd, VARIANT *pv, EXCEPINFO *pe, UINT *pa)
    {
        LogLine(L"[disp] provider.Invoke dispid=%ld flags=0x%04X argc=%u", (long)id, (unsigned)flags,
                pd ? pd->cArgs : 0);
        UNREFERENCED_PARAMETER(pv); UNREFERENCED_PARAMETER(pe); UNREFERENCED_PARAMETER(pa);
        return DISP_E_MEMBERNOTFOUND;
    }

private:
    LONG m_ref;
    LONG m_calls = 0;
    LONG m_cfgLock = 0;
    std::wstring m_caId;
    // 逆向结论：config 不是字节块，而是以 CERTTRANSBLOB 承载的 VARIANT：
    //   cb = VARTYPE（0x200C = VT_ARRAY|VT_VARIANT），pb = SAFEARRAY*（2 列：属性名 / 属性值）
    VARIANT m_cfgVar;
};

LONG CRevInfoProvider::g_objects = 0;

// ------------------------------------------------------------------ 配置界面（中英双语）

// 当前状态文本（对话框里显示，也用于 GetStatus）
//
// 0 条记录是最常见、也最难从 MMC 里看出来的故障（快照路径不对 / 文件是空的 /
// 同步任务没写成功），所以这里把「解析到的路径、文件是否存在、大小、行数」都摊开，
// 让状态页本身就能定位问题。
static std::wstring BuildStatusText(const std::wstring &caId)
{
    Settings st;
    std::wstring file;
    RevDb &db = DbForCA(caId);
    db.SnapshotPath(file, st);
    size_t count = db.Count();
    std::wstring loaded = db.LoadedAt();

    WIN32_FILE_ATTRIBUTE_DATA fad;
    SYSTEMTIME stime;
    ZeroMemory(&stime, sizeof(stime));
    bool exists = GetFileAttributesExW(file.c_str(), GetFileExInfoStandard, &fad) != FALSE;
    unsigned long long size = 0;
    if (exists) {
        size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        FILETIME ftLocal;
        FileTimeToLocalFileTime(&fad.ftLastWriteTime, &ftLocal);
        FileTimeToSystemTime(&ftLocal, &stime);
    }

    wchar_t buf[2048];
    if (IsZhUi()) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
            L"CA：%s\r\n快照文件：%s\r\n"
            L"文件状态：%s（%llu 字节）\r\n"
            L"快照记录：%Iu 条\r\n最后加载：%s\r\n已应答查询：%ld 次\r\n"
            L"快照文件时间：%04u-%02u-%02u %02u:%02u:%02u",
            caId.empty() ? L"(未指定)" : caId.c_str(), file.c_str(),
            exists ? L"存在" : L"不存在", size,
            count, loaded.c_str(), (long)g_queryCount,
            stime.wYear, stime.wMonth, stime.wDay, stime.wHour, stime.wMinute, stime.wSecond);
    } else {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
            L"CA: %s\r\nSnapshot file: %s\r\n"
            L"File state: %s (%llu bytes)\r\n"
            L"Snapshot entries: %Iu\r\nLast loaded: %s\r\nQueries answered: %ld\r\n"
            L"Snapshot file time: %04u-%02u-%02u %02u:%02u:%02u",
            caId.empty() ? L"(not specified)" : caId.c_str(), file.c_str(),
            exists ? L"exists" : L"missing", size,
            count, loaded.c_str(), (long)g_queryCount,
            stime.wYear, stime.wMonth, stime.wDay, stime.wHour, stime.wMinute, stime.wSecond);
    }

    std::wstring out = buf;
    if (count == 0) {
        const wchar_t *hint;
        if (!exists)
            hint = Tr(L"提示：该路径没有文件。检查 provider.ini 的 snapshot 设置，以及计划任务是否在写这个路径。",
                      L"Hint: no file at that path. Check the snapshot setting in provider.ini and whether the scheduled task writes there.");
        else if (size == 0)
            hint = Tr(L"提示：文件存在但为 0 字节，同步任务没有写入任何内容。检查同步任务的历史记录。",
                      L"Hint: the file exists but is empty. The sync task wrote nothing; check its history.");
        else
            hint = Tr(L"提示：文件有内容但没有可解析的行。每行需要「序列号<TAB>处置<TAB>吊销时间」；"
                      L"请确认导出的确实是 certutil -view 的序列号格式。",
                      L"Hint: the file has content but no parsable rows. Each line needs "
                      L"serial<TAB>disposition<TAB>revokedWhen; check that the export is really certutil -view output.");
        out += L"\r\n";
        out += hint;
    }
    return out;
}

static void DumpDialogBmp(HWND hDlg, const std::wstring &path)
{
    RECT rc;
    GetWindowRect(hDlg, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) return;

    HDC hScreen = GetDC(NULL);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    HGDIOBJ old = SelectObject(hMem, hBmp);
    if (!PrintWindow(hDlg, hMem, 2))
        BitBlt(hMem, 0, 0, w, h, hScreen, rc.left, rc.top, SRCCOPY);

    BITMAPFILEHEADER fh;
    BITMAPINFOHEADER ih;
    ZeroMemory(&fh, sizeof(fh));
    ZeroMemory(&ih, sizeof(ih));
    int stride = ((w * 3 + 3) / 4) * 4;
    DWORD imgSize = (DWORD)(stride * h);

    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(ih);
    fh.bfSize = fh.bfOffBits + imgSize;
    ih.biSize = sizeof(ih);
    ih.biWidth = w;
    ih.biHeight = h;
    ih.biPlanes = 1;
    ih.biBitCount = 24;
    ih.biCompression = BI_RGB;
    ih.biSizeImage = imgSize;

    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(f, &fh, sizeof(fh), &wr, NULL);
        WriteFile(f, &ih, sizeof(ih), &wr, NULL);
        std::vector<BYTE> line(stride, 0);
        BITMAPINFO bmi;
        ZeroMemory(&bmi, sizeof(bmi));
        bmi.bmiHeader = ih;
        for (int y = h - 1; y >= 0; y--) {
            if (GetDIBits(hMem, hBmp, y, 1, line.data(), &bmi, DIB_RGB_COLORS) == 0) break;
            WriteFile(f, line.data(), (DWORD)stride, &wr, NULL);
        }
        CloseHandle(f);
        LogLine(L"dialog captured -> %s", path.c_str());
    }

    SelectObject(hMem, old);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}

// 把对话框里每个控件的 ID / 类名 / 文本 / 实际坐标导成 UTF-8 文本（无桌面环境下验证布局用）
static void DumpDialogControls(HWND hDlg, const std::wstring &path)
{
    std::wstring out;
    wchar_t line[1024];

    RECT rcDlg;
    GetWindowRect(hDlg, &rcDlg);
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"dialog rect=(%ld,%ld)-(%ld,%ld)\r\n",
                 rcDlg.left, rcDlg.top, rcDlg.right, rcDlg.bottom);
    out += line;

    for (HWND h = GetWindow(hDlg, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT)) {
        wchar_t cls[64] = {0}, text[512] = {0};
        GetClassNameW(h, cls, _countof(cls));
        GetWindowTextW(h, text, _countof(text));
        int id = GetDlgCtrlID(h);
        RECT r;
        GetWindowRect(h, &r);
        MapWindowPoints(NULL, hDlg, (POINT *)&r, 2);
        _snwprintf_s(line, _countof(line), _TRUNCATE,
                     L"id=%-5d class=%-12s rect=(%ld,%ld,%ld,%ld) text=%s\r\n",
                     id, cls, r.left, r.top, r.right - r.left, r.bottom - r.top, text);
        out += line;
    }

    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    int bytes = WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), NULL, 0, NULL, NULL);
    if (bytes > 0) {
        std::vector<char> buf(bytes);
        WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), buf.data(), bytes, NULL, NULL);
        DWORD wr = 0;
        WriteFile(f, buf.data(), (DWORD)bytes, &wr, NULL);
    }
    CloseHandle(f);
    LogLine(L"dialog controls dumped -> %s", path.c_str());
}

struct DlgContext
{
    Settings *settings;
    std::wstring caId;
    BOOL modified;
    BOOL readOnly;
};

static INT_PTR CALLBACK ConfigDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    DlgContext *ctx = (DlgContext *)GetWindowLongPtrW(hDlg, GWLP_USERDATA);

    switch (msg)
    {
    case WM_INITDIALOG:
    {
        ctx = (DlgContext *)lp;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)ctx);
        Settings *st = ctx->settings;

        SetDlgItemTextW(hDlg, IDC_EDIT_PATH, st->snapshot.c_str());
        wchar_t num[16];
        _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st->checkSeconds);
        SetDlgItemTextW(hDlg, IDC_EDIT_MAXAGE, num);
        _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st->validStatus);
        SetDlgItemTextW(hDlg, IDC_EDIT_VALID, num);
        _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st->revokedStatus);
        SetDlgItemTextW(hDlg, IDC_EDIT_REVOKED, num);
        _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st->unknownStatus);
        SetDlgItemTextW(hDlg, IDC_EDIT_UNKNOWN, num);
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, BuildStatusText(ctx->caId).c_str());

        if (ctx->readOnly) {
            SetDlgItemTextW(hDlg, IDOK, Tr(L"关闭", L"Close"));
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PATH), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_BTN_BROWSE), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_MAXAGE), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_VALID), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_REVOKED), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_UNKNOWN), FALSE);
        }

        // 截图自检模式：OCSPDBPROVIDER_CAPTURE=1 时把窗口存成 BMP，然后自动点确定
        wchar_t cap[8] = {0};
        if (GetEnvironmentVariableW(L"OCSPDBPROVIDER_CAPTURE", cap, _countof(cap)) > 0 && cap[0] == L'1')
            SetTimer(hDlg, 1, 800, NULL);
        return TRUE;
    }

    case WM_TIMER:
        if (wp == 1) {
            KillTimer(hDlg, 1);
            DumpDialogBmp(hDlg, JoinPath(CaptureDir(), L"uitest.bmp"));
            DumpDialogControls(hDlg, JoinPath(CaptureDir(), L"uitest-controls.txt"));
            PostMessageW(hDlg, WM_COMMAND, ctx && ctx->readOnly ? IDCANCEL : IDOK, 0);
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDC_BTN_BROWSE:
        {
            wchar_t path[MAX_PATH * 2] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PATH, path, _countof(path));
            OPENFILENAMEW ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hDlg;
            ofn.lpstrFile = path;
            ofn.nMaxFile = _countof(path);
            ofn.lpstrFilter = Tr(L"快照文件 (*.dat)\0*.dat\0所有文件 (*.*)\0*.*\0\0",
                                 L"Snapshot files (*.dat)\0*.dat\0All files (*.*)\0*.*\0\0");
            ofn.lpstrTitle = Tr(L"选择证书数据库快照文件", L"Select the CA database snapshot file");
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn))
                SetDlgItemTextW(hDlg, IDC_EDIT_PATH, path);
            return TRUE;
        }
        case IDC_BTN_RELOAD:
            DbForCA(ctx->caId).Reload();
            SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, BuildStatusText(ctx->caId).c_str());
            return TRUE;

        case IDOK:
        {
            if (ctx->readOnly) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            Settings *st = ctx->settings;
            wchar_t path[MAX_PATH * 2] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PATH, path, _countof(path));
            if (path[0] == 0) {
                MessageBoxW(hDlg, Tr(L"快照文件路径不能为空。", L"The snapshot file path cannot be empty."),
                            Tr(L"证书数据库吊销提供程序", L"CA Database Revocation Provider"), MB_ICONWARNING);
                return TRUE;
            }
            if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
                MessageBoxW(hDlg, Tr(L"指定的快照文件不存在，请检查路径。",
                                     L"The specified snapshot file does not exist. Please check the path."),
                            Tr(L"证书数据库吊销提供程序", L"CA Database Revocation Provider"), MB_ICONWARNING);
                return TRUE;
            }
            st->snapshot = path;
            st->checkSeconds  = GetDlgItemInt(hDlg, IDC_EDIT_MAXAGE,   NULL, FALSE);
            st->validStatus   = GetDlgItemInt(hDlg, IDC_EDIT_VALID,    NULL, FALSE);
            st->revokedStatus = GetDlgItemInt(hDlg, IDC_EDIT_REVOKED,  NULL, FALSE);
            st->unknownStatus = GetDlgItemInt(hDlg, IDC_EDIT_UNKNOWN,  NULL, FALSE);
            if (st->checkSeconds < 0 || st->checkSeconds > 3600) st->checkSeconds = 2;
            if (!ConfigSaveCa(ctx->caId, *st)) LogLine(L"write ini failed: %lu", GetLastError());
            DbForCA(ctx->caId).Reload();          // 让新设置立刻生效
            ctx->modified = TRUE;
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

// 显示配置对话框；返回 TRUE 表示用户确定并保存
static BOOL ShowConfigDialog(HWND parent, BOOL readOnly, const std::wstring &caId, Settings &st)
{
    if (!g_hInst) return FALSE;
    DlgContext ctx;
    ctx.settings = &st;
    ctx.caId = caId;
    ctx.modified = FALSE;
    ctx.readOnly = readOnly;
    // 两种语言的对话框各一份资源，按 UI 语言显式选择（不依赖资源 LANGUAGE 回退）
    DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IsZhUi() ? IDD_CONFIG_ZH : IDD_CONFIG_EN),
                    parent, ConfigDlgProc, (LPARAM)&ctx);
    return ctx.modified;
}

// ------------------------------------------------------------------ manager（MMC 配置/状态入口）

class CProviderManager : public IOCSPRevInfoProviderManager
{
public:
    CProviderManager() : m_ref(1) { InterlockedIncrement(&CRevInfoProvider::g_objects); }
    ~CProviderManager() { InterlockedDecrement(&CRevInfoProvider::g_objects); }
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IOCSPRevInfoProviderManager)) {
            *ppv = static_cast<IOCSPRevInfoProviderManager *>(this);
            AddRef();
            LogQI(L"manager", riid, S_OK);
            return S_OK;
        }
        LogQI(L"manager", riid, E_NOINTERFACE);
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef()  { return (ULONG)InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release()
    {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }

    STDMETHODIMP GetProviderInformation(BSTR *pName, BSTR *pDesc)
    {
        if (pName) *pName = SysAllocString(Tr(L"证书数据库吊销提供程序", L"CA Database Revocation Provider"));
        if (pDesc) *pDesc = SysAllocString(Tr(
            L"吊销状态取自 CA 证书数据库的快照，不依赖 CRL；吊销后最多 1 分钟生效。",
            L"Revocation state comes from a CA database snapshot instead of a CRL; "
            L"revocation propagates within one minute."));
        return S_OK;
    }

    STDMETHODIMP Configure(HWND hwndParent, BSTR bstrCAConfigId, CERTTRANSBLOB *pCACert,
                           CERTTRANSBLOB *pInConfig, BOOL *pModified, CERTTRANSBLOB *pOutConfig)
    {
        UNREFERENCED_PARAMETER(pCACert);
        if (pModified) *pModified = FALSE;
        if (pOutConfig) { pOutConfig->cb = 0; pOutConfig->pb = NULL; }

        std::wstring caId = bstrCAConfigId ? bstrCAConfigId : L"";
        Settings st = ConfigEffectiveFor(caId);
        BOOL ok = ShowConfigDialog(hwndParent, FALSE, caId, st);
        if (pModified) *pModified = ok;

        // 配置必须回环：把调用方传进来的属性表原样交回去（服务据此持久化）。
        // 传入的 CERTTRANSBLOB 其实是 VARIANT（cb 存放 VARTYPE：0x200C=VT_ARRAY|VT_VARIANT，
        // 0x2011=VT_ARRAY|VT_UI1），所以这里按 vt 通用处理，不写死某一种。
        if (pOutConfig && pInConfig && pInConfig->pb &&
            (pInConfig->cb == 0x200C || pInConfig->cb == 0x2011 || pInConfig->cb == 0x2008)) {
            VARIANT src, copy;
            VariantInit(&src);
            VariantInit(&copy);
            src.vt = (VARTYPE)pInConfig->cb;
            src.parray = (SAFEARRAY *)pInConfig->pb;
            if (SUCCEEDED(VariantCopy(&copy, &src))) {
                pOutConfig->cb = (ULONG)copy.vt;
                pOutConfig->pb = (PBYTE)copy.parray;
                copy.parray = NULL;
            }
        }
        LogLine(L"Configure(%s) hwnd=%p inCfg.vt=0x%04X modified=%d",
                caId.c_str(), (void *)hwndParent,
                pInConfig ? (unsigned)pInConfig->cb : 0, ok ? 1 : 0);
        return S_OK;
    }

    STDMETHODIMP View(HWND hwndParent, BSTR bstrCAConfigId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pInConfig)
    {
        UNREFERENCED_PARAMETER(pCACert);
        UNREFERENCED_PARAMETER(pInConfig);
        std::wstring caId = bstrCAConfigId ? bstrCAConfigId : L"";
        Settings st = ConfigEffectiveFor(caId);
        ShowConfigDialog(hwndParent, TRUE, caId, st);
        LogLine(L"View(%s)", caId.c_str());
        return S_OK;
    }

    STDMETHODIMP GetStatus(BSTR bstrCAConfigId, CERTTRANSBLOB *pCACert, CERTTRANSBLOB *pInConfig,
                           VARIANT *pStatus, HRESULT *pHR)
    {
        UNREFERENCED_PARAMETER(pCACert);
        UNREFERENCED_PARAMETER(pInConfig);
        std::wstring caId = bstrCAConfigId ? bstrCAConfigId : L"";
        LogLine(L"[mgr] GetStatus(ca=%s pStatus=%p pHR=%p inCfg.vt=0x%04X)", caId.c_str(),
                (void *)pStatus, (void *)pHR, pInConfig ? (unsigned)pInConfig->cb : 0);

        // 契约来自 OCSPAdminNative.dll!DllRevProvGetStatus + 托管侧 RevProvMgr.RevProvGetStatus 的
        // `castclass String[]`：这里必须给出【BSTR 数组】(VT_ARRAY|VT_BSTR)，给单个 BSTR 会在托管侧
        // 抛 InvalidCastException，而该异常被 OCSPError 判为“不可恢复”后重抛 → 直接崩掉 mmc.exe。
        std::wstring text = BuildStatusText(caId);
        std::vector<std::wstring> lines;
        size_t pos = 0;
        while (pos <= text.size()) {
            size_t nl = text.find(L"\r\n", pos);
            if (nl == std::wstring::npos) {
                if (pos < text.size()) lines.push_back(text.substr(pos));
                break;
            }
            lines.push_back(text.substr(pos, nl - pos));
            pos = nl + 2;
        }
        if (lines.empty()) lines.push_back(L"");

        SAFEARRAYBOUND bound;
        bound.lLbound = 0;
        bound.cElements = (ULONG)lines.size();
        SAFEARRAY *sa = SafeArrayCreate(VT_BSTR, 1, &bound);
        if (!sa) return E_OUTOFMEMORY;
        for (LONG i = 0; i < (LONG)lines.size(); i++) {
            BSTR item = SysAllocString(lines[i].c_str());
            if (!item) { SafeArrayDestroy(sa); return E_OUTOFMEMORY; }
            if (FAILED(SafeArrayPutElement(sa, &i, item))) {
                SysFreeString(item);
                SafeArrayDestroy(sa);
                return E_UNEXPECTED;
            }
            SysFreeString(item);            // 数组已持有自己的副本
        }

        if (pStatus) {
            VariantInit(pStatus);
            pStatus->vt = VT_ARRAY | VT_BSTR;   // 0x2008 -> string[]
            pStatus->parray = sa;
        } else {
            SafeArrayDestroy(sa);
        }
        if (pHR) *pHR = S_OK;
        LogLine(L"[mgr] GetStatus -> string[%u]", (unsigned)lines.size());
        return S_OK;
    }

    STDMETHODIMP Initialize_(BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *pOut)
    {
        if (pOut) { pOut->cb = 0; pOut->pb = NULL; }
        return S_OK;
    }

    // ---- dual 接口的 IDispatch 槽位 ----
    STDMETHODIMP GetTypeInfoCount(UINT *pc)
    {
        LogLine(L"[disp] manager.GetTypeInfoCount");
        if (pc) *pc = 0;
        return S_OK;
    }
    STDMETHODIMP GetTypeInfo(UINT, LCID, ITypeInfo **pp)
    {
        LogLine(L"[disp] manager.GetTypeInfo");
        if (pp) *pp = NULL;
        return E_NOTIMPL;
    }
    STDMETHODIMP GetIDsOfNames(REFIID, LPOLESTR *names, UINT c, LCID, DISPID *ids)
    {
        LogLine(L"[disp] manager.GetIDsOfNames count=%u name0=%s", c, (c && names) ? names[0] : L"");
        return DISP_E_UNKNOWNNAME;
    }
    STDMETHODIMP Invoke(DISPID id, REFIID, LCID, WORD flags, DISPPARAMS *pd, VARIANT *pv, EXCEPINFO *pe, UINT *pa)
    {
        LogLine(L"[disp] manager.Invoke dispid=%ld flags=0x%04X argc=%u", (long)id, (unsigned)flags,
                pd ? pd->cArgs : 0);
        UNREFERENCED_PARAMETER(pv); UNREFERENCED_PARAMETER(pe); UNREFERENCED_PARAMETER(pa);
        return DISP_E_MEMBERNOTFOUND;
    }

private:
    LONG m_ref;
};

IUnknown *CreateManagerInstance()
{
    CProviderManager *p = new (std::nothrow) CProviderManager();
    return p ? static_cast<IUnknown *>(static_cast<IOCSPRevInfoProviderManager *>(p)) : NULL;
}

// manager 单例：静态持有一个引用（永不释放），保证 DllCanUnloadNow 不会在 MMC 还拿着
// 指针时把 DLL 卸掉；每次取用再 AddRef 一次交给调用方。
IUnknown *GetSharedManager()
{
    static IUnknown *volatile s_mgr = NULL;
    IUnknown *p = s_mgr;
    if (!p) {
        IUnknown *n = CreateManagerInstance();
        if (!n) return NULL;
        IUnknown *prev = (IUnknown *)InterlockedCompareExchangePointer((PVOID volatile *)&s_mgr, n, NULL);
        if (prev) { n->Release(); p = prev; } else { p = n; }
    }
    p->AddRef();
    return p;
}


// ------------------------------------------------------------------ 类厂 / 导出

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : m_ref(1) {}
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
            *ppv = static_cast<IClassFactory *>(this);
        if (!*ppv) return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    STDMETHODIMP_(ULONG) AddRef()  { return (ULONG)InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release()
    {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }
    STDMETHODIMP CreateInstance(IUnknown *outer, REFIID riid, void **ppv)
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        CRevInfoProvider *p = new (std::nothrow) CRevInfoProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL lock)
    {
        if (lock) InterlockedIncrement(&CRevInfoProvider::g_objects);
        else InterlockedDecrement(&CRevInfoProvider::g_objects);
        return S_OK;
    }

private:
    LONG m_ref;
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        g_csInit = true;
        InitializeCriticalSection(&g_dbCs);
        g_dbCsInit = true;
        wchar_t path[MAX_PATH];
        g_hInst = hModule;
        if (GetModuleFileNameW(hModule, path, MAX_PATH)) g_dllPath = path;
        LogLine(L"provider DLL loaded: %s (install dir: %s)", g_dllPath.c_str(), InstallDir().c_str());
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_csInit) { LogLine(L"provider DLL unloaded"); DeleteCriticalSection(&g_cs); g_csInit = false; }
        if (g_dbCsInit) { DeleteCriticalSection(&g_dbCs); g_dbCsInit = false; }
    }
    return TRUE;
}

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    if (!IsEqualCLSID(rclsid, CLSID_OcspDbProvider)) return CLASS_E_CLASSNOTAVAILABLE;
    CClassFactory *f = new (std::nothrow) CClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

extern "C" HRESULT WINAPI DllCanUnloadNow(void)
{
    return CRevInfoProvider::g_objects == 0 ? S_OK : S_FALSE;
}

extern "C" HRESULT WINAPI DllRegisterServer(void)
{
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_OcspDbProvider, clsidStr, 64);

    wchar_t key[512];
    _snwprintf_s(key, _countof(key), _TRUNCATE, L"CLSID\\%s", clsidStr);
    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return E_ACCESSDENIED;
    const wchar_t *friendly = Tr(L"证书数据库吊销提供程序", L"CA Database Revocation Provider");
    RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)friendly,
                   (DWORD)((wcslen(friendly) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);

    _snwprintf_s(key, _countof(key), _TRUNCATE, L"CLSID\\%s\\InprocServer32", clsidStr);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)g_dllPath.c_str(),
                       (DWORD)((g_dllPath.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hk, L"ThreadingModel", 0, REG_SZ, (const BYTE *)L"Both", sizeof(L"Both"));
        RegCloseKey(hk);
    }

    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, PROVIDER_PROGID, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)friendly,
                       (DWORD)((wcslen(friendly) + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }
    _snwprintf_s(key, _countof(key), _TRUNCATE, L"%s\\CLSID", PROVIDER_PROGID);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)clsidStr, (DWORD)((wcslen(clsidStr) + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }

    // 让 provider 自己能定位安装目录。
    //
    // 这里必须用 DLL 自己的目录，不能用 InstallDir()：后者在注册表还没有这个值时
    // 会退回 %ProgramData%\OcspDbProvider，于是把错误的默认值写进注册表，之后
    // 解析就一直指向那个空目录（快照 0 条）。DLL 所在目录才是权威答案。
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_ROOT, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        std::wstring dir = InstallDir();
        if (!g_dllPath.empty()) {
            size_t slash = g_dllPath.find_last_of(L"\\/");
            if (slash != std::wstring::npos) dir = TrimTrailingSlash(g_dllPath.substr(0, slash));
        }
        RegSetValueExW(hk, L"InstallDir", 0, REG_SZ, (const BYTE *)dir.c_str(),
                       (DWORD)((dir.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
        LogLine(L"DllRegisterServer: InstallDir=%s", dir.c_str());
    }
    return S_OK;
}

extern "C" HRESULT WINAPI DllUnregisterServer(void)
{
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_OcspDbProvider, clsidStr, 64);
    wchar_t key[512];
    _snwprintf_s(key, _countof(key), _TRUNCATE, L"CLSID\\%s", clsidStr);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, key);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, PROVIDER_PROGID);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, LEGACY_PROGID);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, REG_ROOT);
    return S_OK;
}
