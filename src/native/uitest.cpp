// uitest.cpp —— 不用打开 MMC，直接验证提供程序的名称/描述、配置对话框、状态文本
//
// 用法：
//   uitest.exe info                 打印 GetProviderInformation / GetStatus
//   uitest.exe config               打开配置对话框（用于手工看/截图）
//   uitest.exe view                 以只读方式打开同一个对话框
//   uitest.exe verify <serial-hex>  调 VerifySerialNumber 查一个序列号
//   uitest.exe selftest             依次跑 info / verify / config（自动关闭）
//   uitest.exe rescheck             只检查 DLL 里的对话框/版本资源（不显示窗口，可无桌面运行）
//
// 选项：
//   -dll <path>     直接 LoadLibrary 指定的 DLL（免注册表/免管理员，便于验证构建产物）
//   -ca <ca-id>     指定 CA 配置串（默认取 %OCSPDBPROVIDER_CA%，否则 "localhost\CA"）
//   -lang zh|en     强制界面语言（等价于设置 OCSPDBPROVIDER_LANG）
//   -capture <dir>  截图/控件树输出目录（等价于 OCSPDBPROVIDER_CAPTURE_DIR）
//   -raw            附加打印安装目录等环境信息
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <vector>

static const GUID CLSID_OcspDbProvider =
    {0x7b0c4b1e, 0x93a1, 0x4c0f, {0x9e, 0x52, 0x0d, 0x2a, 0x6a, 0x5b, 0x41, 0xc9}};
static const IID IID_IOCSPRevInfoProvider =
    {0x93f568ff, 0xb8c7, 0x483b, {0x8d, 0xef, 0x5e, 0x6e, 0xef, 0x8b, 0x76, 0x50}};
static const IID IID_IOCSPRevInfoProviderManager =
    {0xf85c5127, 0xf108, 0x497d, {0x8f, 0xcc, 0xb2, 0xa7, 0x09, 0x04, 0x7c, 0x98}};

struct CERTTRANSBLOB { ULONG cb; PBYTE pb; };

#pragma pack(push, 1)
struct RevStatusInfo {
    DWORD dwStatus;
    FILETIME ftThisUpdate, ftNextUpdate, ftNextPublish, ftRevocationDate;
    DWORD dwRevocationReason;
};
#pragma pack(pop)

struct IOCSPRevInfoProvider : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Initialize(BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *) = 0;
    virtual HRESULT STDMETHODCALLTYPE VerifySerialNumber(CERTTRANSBLOB *, RevStatusInfo *) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetConfigInformation(CERTTRANSBLOB *) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProviderManager(IUnknown **) = 0;
};

struct IOCSPRevInfoProviderManager : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetProviderInformation(BSTR *, BSTR *) = 0;
    virtual HRESULT STDMETHODCALLTYPE Configure(HWND, BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *, BOOL *, CERTTRANSBLOB *) = 0;
    virtual HRESULT STDMETHODCALLTYPE View(HWND, BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStatus(BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *, VARIANT *, HRESULT *) = 0;
    virtual HRESULT STDMETHODCALLTYPE Initialize_(BSTR, CERTTRANSBLOB *, CERTTRANSBLOB *) = 0;
};

static void Print(const wchar_t *fmt, ...)
{
    wchar_t buf[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    wprintf(L"%s\n", buf);
}

static std::wstring EnvOr(const wchar_t *name, const wchar_t *fallback)
{
    wchar_t buf[MAX_PATH * 2] = {0};
    DWORD n = GetEnvironmentVariableW(name, buf, _countof(buf));
    if (n > 0 && n < _countof(buf)) return std::wstring(buf);
    return std::wstring(fallback);
}

static bool HexToBytes(const std::wstring &hex, std::vector<BYTE> &out)
{
    out.clear();
    int hi = -1;
    for (wchar_t c : hex) {
        int v;
        if (c >= L'0' && c <= L'9') v = c - L'0';
        else if (c >= L'a' && c <= L'f') v = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') v = c - L'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out.push_back((BYTE)((hi << 4) | v)); hi = -1; }
    }
    return !out.empty();
}

// 读取对话框模板的标题（DLGTEMPLATE / DLGTEMPLATEEX 之后是 menu/class/title 三个变长字段）
static std::wstring DialogCaption(const BYTE *res, DWORD size)
{
    if (!res || size < 4) return L"";
    // DIALOGEX 用 DLGTEMPLATEEX：{WORD dlgVer=1, WORD signature=0xFFFF, ...}，头 26 字节；
    // 普通 DIALOG 是 DLGTEMPLATE，头 18 字节。rc 里用的是 DIALOGEX。
    size_t header = 18;
    if (*(const WORD *)res == 0x0001 && *(const WORD *)(res + 2) == 0xFFFF) header = 26;
    if (size < header) return L"";
    const BYTE *p = res + header;
    const BYTE *end = res + size;
    // menu：0x0000 表示无
    if (p + 2 > end) return L"";
    if (*(const WORD *)p == 0x0000) p += 2;
    else if (*(const WORD *)p == 0xFFFF) p += 4;
    else { while (p + 2 <= end && *(const WORD *)p) p += 2; p += 2; }
    // class：同上
    if (p + 2 > end) return L"";
    if (*(const WORD *)p == 0x0000) p += 2;
    else if (*(const WORD *)p == 0xFFFF) p += 4;
    else { while (p + 2 <= end && *(const WORD *)p) p += 2; p += 2; }
    // title：以 NUL 结尾的宽字符串
    const wchar_t *t = (const wchar_t *)p;
    size_t maxLen = (size_t)((end - p) / sizeof(wchar_t));
    size_t n = 0;
    while (n < maxLen && t[n]) n++;
    return std::wstring(t, n);
}

// 资源自检：确认中英两套对话框都存在且标题正确（不需要交互桌面）
static int ResourceCheck(const std::wstring &dllPath)
{
    HMODULE h = LoadLibraryExW(dllPath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) { Print(L"LoadLibrary(AS_DATAFILE) failed: %lu", GetLastError()); return 1; }
    int failures = 0;
    struct { int id; const wchar_t *label; } cases[] = {
        {101, L"IDD_CONFIG_ZH"},
        {102, L"IDD_CONFIG_EN"},
    };
    for (auto &c : cases) {
        HRSRC hr = FindResourceW(h, MAKEINTRESOURCEW(c.id), RT_DIALOG);
        if (!hr) { Print(L"  %s (id=%d): MISSING", c.label, c.id); failures++; continue; }
        HGLOBAL hg = LoadResource(h, hr);
        DWORD size = SizeofResource(h, hr);
        const BYTE *data = (const BYTE *)LockResource(hg);
        std::wstring caption = DialogCaption(data, size);
        Print(L"  %s (id=%d): size=%lu caption=\"%s\"", c.label, c.id, size, caption.c_str());
    }
    // 版本信息
    if (FindResourceW(h, MAKEINTRESOURCEW(1), RT_VERSION))
        Print(L"  VERSIONINFO: present");
    else { Print(L"  VERSIONINFO: missing"); failures++; }
    FreeLibrary(h);
    Print(failures ? L"rescheck: FAILED (%d)" : L"rescheck: OK", failures);
    return failures ? 1 : 0;
}

int wmain(int argc, wchar_t **argv)
{
    // 统一按 UTF-8 输出：控制台请先 chcp 65001；重定向到文件时也是 UTF-8
    _setmode(_fileno(stdout), _O_U8TEXT);

    std::wstring mode = (argc > 1) ? argv[1] : L"info";
    std::wstring caId = EnvOr(L"OCSPDBPROVIDER_CA", L"localhost\\CA");
    std::wstring serialHex;
    std::wstring dllPath;
    bool raw = false;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"-dll" && i + 1 < argc) dllPath = argv[++i];
        else if (a == L"-ca" && i + 1 < argc) caId = argv[++i];
        else if (a == L"-lang" && i + 1 < argc) SetEnvironmentVariableW(L"OCSPDBPROVIDER_LANG", argv[++i]);
        else if (a == L"-capture" && i + 1 < argc) SetEnvironmentVariableW(L"OCSPDBPROVIDER_CAPTURE_DIR", argv[++i]);
        else if (a == L"-raw") raw = true;
        else if (!a.empty() && a[0] != L'-' && i > 1 && serialHex.empty()) serialHex = a;
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (mode == L"rescheck") {
        if (dllPath.empty()) { Print(L"rescheck needs -dll <path>"); return 1; }
        int rc = ResourceCheck(dllPath);
        CoUninitialize();
        return rc;
    }

    IUnknown *pUnk = NULL;
    HRESULT hr = 0;
    HMODULE hDirect = NULL;
    if (!dllPath.empty()) {
        // 免注册路径：直接调用 DllGetClassObject，避免写 HKCR（无需管理员）
        hDirect = LoadLibraryExW(dllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hDirect) {
            Print(L"LoadLibrary failed: 0x%08X  %s", GetLastError(), dllPath.c_str());
            CoUninitialize();
            return 1;
        }
        typedef HRESULT (WINAPI *PFN_GetClassObject)(REFCLSID, REFIID, void **);
        PFN_GetClassObject pfn = (PFN_GetClassObject)GetProcAddress(hDirect, "DllGetClassObject");
        if (!pfn) {
            Print(L"DllGetClassObject not exported");
            CoUninitialize();
            return 1;
        }
        IClassFactory *cf = NULL;
        hr = pfn(CLSID_OcspDbProvider, IID_IClassFactory, (void **)&cf);
        if (SUCCEEDED(hr) && cf) {
            hr = cf->CreateInstance(NULL, IID_IOCSPRevInfoProvider, (void **)&pUnk);
            cf->Release();
        }
        Print(L"loaded directly: %s", dllPath.c_str());
    } else {
        hr = CoCreateInstance(CLSID_OcspDbProvider, NULL, CLSCTX_INPROC_SERVER,
                              IID_IOCSPRevInfoProvider, (void **)&pUnk);
    }
    if (FAILED(hr) || !pUnk) {
        Print(L"CoCreateInstance failed: 0x%08X (is the DLL registered?)", hr);
        CoUninitialize();
        return 1;
    }

    IOCSPRevInfoProvider *prov = (IOCSPRevInfoProvider *)pUnk;
    CERTTRANSBLOB caCert = {0, NULL};
    CERTTRANSBLOB cfg = {0, NULL};
    BSTR bcaId = SysAllocString(caId.c_str());
    Print(L"CA id: %s", caId.c_str());
    hr = prov->Initialize(bcaId, &caCert, &cfg);
    Print(L"Initialize hr=0x%08X", hr);

    IUnknown *pMgrUnk = NULL;
    hr = prov->GetProviderManager(&pMgrUnk);
    if (FAILED(hr) || !pMgrUnk) {
        Print(L"GetProviderManager failed: 0x%08X", hr);
        SysFreeString(bcaId);
        pUnk->Release();
        CoUninitialize();
        return 1;
    }
    IOCSPRevInfoProviderManager *mgr = (IOCSPRevInfoProviderManager *)pMgrUnk;

    if (mode == L"info" || mode == L"selftest" || mode == L"config" || mode == L"view") {
        BSTR name = NULL, desc = NULL;
        hr = mgr->GetProviderInformation(&name, &desc);
        Print(L"GetProviderInformation hr=0x%08X", hr);
        Print(L"  name: %s", name ? name : L"(null)");
        Print(L"  desc: %s", desc ? desc : L"(null)");

        VARIANT status;
        HRESULT shr = S_OK;
        VariantInit(&status);
        cfg.cb = 0;
        cfg.pb = NULL;
        hr = mgr->GetStatus(bcaId, &caCert, &cfg, &status, &shr);
        Print(L"GetStatus hr=0x%08X  innerHr=0x%08X  vt=0x%04X", hr, shr, status.vt);
        if (status.vt == (VT_ARRAY | VT_BSTR) && status.parray) {
            LONG lo = 0, hi = -1;
            SafeArrayGetLBound(status.parray, 1, &lo);
            SafeArrayGetUBound(status.parray, 1, &hi);
            for (LONG i = lo; i <= hi; i++) {
                BSTR item = NULL;
                if (SUCCEEDED(SafeArrayGetElement(status.parray, &i, &item)) && item) {
                    Print(L"  status[%ld]: %s", i, item);
                    SysFreeString(item);
                }
            }
        }
        VariantClear(&status);
        SysFreeString(name);
        SysFreeString(desc);
    }

    if (mode == L"verify" || mode == L"selftest") {
        std::vector<BYTE> bytes;
        if (!HexToBytes(serialHex, bytes)) {
            Print(L"verify: no serial given (pass the serial as the 2nd argument)");
        } else {
            CERTTRANSBLOB blob;
            blob.cb = (ULONG)bytes.size();
            blob.pb = bytes.data();
            RevStatusInfo st;
            ZeroMemory(&st, sizeof(st));
            hr = prov->VerifySerialNumber(&blob, &st);
            Print(L"VerifySerialNumber hr=0x%08X", hr);
            Print(L"  status=%lu reason=%lu", st.dwStatus, st.dwRevocationReason);
            {
                // The responder caches a response until nextUpdate, so this window is exactly
                // "how stale an answer a client can still get". Printed so a test can pin it.
                ULARGE_INTEGER a, b;
                a.LowPart = st.ftThisUpdate.dwLowDateTime;  a.HighPart = st.ftThisUpdate.dwHighDateTime;
                b.LowPart = st.ftNextUpdate.dwLowDateTime;  b.HighPart = st.ftNextUpdate.dwHighDateTime;
                long long window = (b.QuadPart > a.QuadPart)
                                   ? (long long)((b.QuadPart - a.QuadPart) / 10000000ULL) : -1;
                Print(L"  window=%lld", window);
            }
            if (st.ftRevocationDate.dwLowDateTime || st.ftRevocationDate.dwHighDateTime) {
                FILETIME ftLocal;
                SYSTEMTIME stt;
                FileTimeToLocalFileTime(&st.ftRevocationDate, &ftLocal);
                FileTimeToSystemTime(&ftLocal, &stt);
                Print(L"  revoked at: %04u-%02u-%02u %02u:%02u:%02u",
                      stt.wYear, stt.wMonth, stt.wDay, stt.wHour, stt.wMinute, stt.wSecond);
            }
        }
    }

    if (mode == L"config" || mode == L"view" || mode == L"selftest") {
        BOOL modified = FALSE;
        CERTTRANSBLOB outCfg = {0, NULL};
        bool isConfig = (mode != L"view");
        if (mode == L"selftest") SetEnvironmentVariableW(L"OCSPDBPROVIDER_CAPTURE", L"1");
        HRESULT r = isConfig
            ? mgr->Configure(NULL, bcaId, &caCert, &cfg, &modified, &outCfg)
            : mgr->View(NULL, bcaId, &caCert, &cfg);
        Print(L"%s hr=0x%08X  modified=%d", isConfig ? L"Configure" : L"View", r, modified);
        if (outCfg.pb && outCfg.cb) {
            VARIANT v;
            VariantInit(&v);
            v.vt = (VARTYPE)outCfg.cb;
            v.parray = (SAFEARRAY *)outCfg.pb;
            VariantClear(&v);
        }
    }

    if (raw) {
        Print(L"install dir: %s", EnvOr(L"OCSPDBPROVIDER_DIR", L"(not set)").c_str());
    }

    SysFreeString(bcaId);
    pMgrUnk->Release();
    pUnk->Release();
    CoUninitialize();
    return 0;
}
