// OcspDbConfig.cpp —— 配置模型的实现（提供程序与配置工具共享）
#include "OcspDbConfig.h"

#include <stdio.h>
#include <map>
#include <string>
#include <vector>

// ------------------------------------------------------------------ 路径

static bool ReadRegString(HKEY root, const wchar_t *sub, const wchar_t *value, std::wstring &out)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = 0;
    bool ok = false;
    if (RegQueryValueExW(hk, value, NULL, &type, NULL, &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && size > sizeof(wchar_t)) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, 0);
        if (RegQueryValueExW(hk, value, NULL, &type, (LPBYTE)buf.data(), &size) == ERROR_SUCCESS) {
            std::wstring v(buf.data());
            if (type == REG_EXPAND_SZ) {
                std::vector<wchar_t> e(v.size() + MAX_PATH * 2, 0);
                DWORD n = ExpandEnvironmentStringsW(v.c_str(), e.data(), (DWORD)e.size());
                if (n > 0 && n <= e.size()) v.assign(e.data(), n - 1);
            }
            if (!v.empty()) { out = v; ok = true; }
        }
    }
    RegCloseKey(hk);
    return ok;
}

std::wstring TrimTrailingSlash(std::wstring s)
{
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    return s;
}

std::wstring JoinPath(const std::wstring &dir, const std::wstring &name)
{
    if (dir.empty()) return name;
    std::wstring r = dir;
    if (r.back() != L'\\') r += L'\\';
    r += name;
    return r;
}

static std::wstring ResolveInstallDir()
{
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableW(L"OCSPDBPROVIDER_DIR", buf, _countof(buf));
    if (n > 0 && n < _countof(buf)) return TrimTrailingSlash(buf);

    std::wstring reg;
    if (ReadRegString(HKEY_LOCAL_MACHINE, OCSPDB_REG_ROOT, L"InstallDir", reg))
        return TrimTrailingSlash(reg);

    n = GetEnvironmentVariableW(L"ProgramData", buf, _countof(buf));
    if (n > 0 && n < _countof(buf)) return JoinPath(TrimTrailingSlash(buf), L"OcspDbProvider");
    n = GetEnvironmentVariableW(L"ALLUSERSPROFILE", buf, _countof(buf));
    if (n > 0 && n < _countof(buf)) return JoinPath(TrimTrailingSlash(buf), L"OcspDbProvider");

    return L"C:\\ProgramData\\OcspDbProvider";
}

const std::wstring &InstallDir()
{
    static const std::wstring kDir = ResolveInstallDir();
    return kDir;
}

std::wstring IniPath() { return JoinPath(InstallDir(), L"provider.ini"); }
std::wstring DataDir() { return JoinPath(InstallDir(), L"data"); }

std::wstring SafeFileName(const std::wstring &s)
{
    std::wstring out;
    for (wchar_t c : s) {
        if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.')
            out.push_back(c);
        else
            out.push_back(L'_');
    }
    if (out.empty()) out = L"default";
    return out;
}

// ------------------------------------------------------------------ 界面语言

bool IsZhUi()
{
    static int s_zh = -1;
    if (s_zh < 0) {
        s_zh = -2;
        wchar_t v[16] = {0};
        if (GetEnvironmentVariableW(L"OCSPDBPROVIDER_LANG", v, _countof(v)) > 0) {
            if (v[0] == L'z' || v[0] == L'Z') s_zh = 1;
            else if (v[0] == L'e' || v[0] == L'E') s_zh = 0;
        }
        if (s_zh < 0) s_zh = (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE) ? 1 : 0;
    }
    return s_zh != 0;
}

const wchar_t *Tr(const wchar_t *zh, const wchar_t *en)
{
    return IsZhUi() ? zh : en;
}

// ------------------------------------------------------------------ 文件读写

std::string ReadTextFileUtf8(const std::wstring &path)
{
    std::string text;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return text;
    char buf[65536];
    DWORD read = 0;
    while (ReadFile(h, buf, sizeof(buf), &read, NULL) && read > 0) text.append(buf, read);
    CloseHandle(h);
    return text;
}

bool WriteTextFileUtf8(const std::wstring &path, const std::string &text)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(h, text.data(), (DWORD)text.size(), &written, NULL);
    CloseHandle(h);
    return written == text.size();
}

// ------------------------------------------------------------------ 存储

namespace {

struct Store {
    CaConfig defaults;
    std::map<std::wstring, CaConfig> cas;
    bool loaded = false;
    CRITICAL_SECTION cs;
    Store() { InitializeCriticalSection(&cs); }
};

// 故意不析构：DLL 卸载期间可能还有线程在用，泄漏几十字节换取安全
Store &S()
{
    static Store *s = new Store();
    return *s;
}

void ApplyKey(CaConfig &cfg, const std::string &k, const std::string &v)
{
    if (k == "snapshot" && !v.empty()) {
        wchar_t w[MAX_PATH * 2];
        if (MultiByteToWideChar(CP_UTF8, 0, v.c_str(), -1, w, _countof(w)) > 0) cfg.snapshot = w;
    } else if (k == "checkseconds")   cfg.checkSeconds  = atoi(v.c_str());
    else if (k == "validstatus")      cfg.validStatus   = atoi(v.c_str());
    else if (k == "revokedstatus")    cfg.revokedStatus = atoi(v.c_str());
    else if (k == "unknownstatus")    cfg.unknownStatus = atoi(v.c_str());
    else if (k == "responseseconds")  cfg.responseSeconds = atoi(v.c_str());
}

// 配置文件是 UTF-8 的 key=value；[default] 或文件头的平铺键对所有 CA 生效，
// [ca:<ca-id>] 只覆盖单个 CA。老的平铺格式（无分段）按 default 处理，保持向后兼容。
void LoadLocked(Store &s)
{
    s.defaults = CaConfig();
    s.cas.clear();
    std::string text = ReadTextFileUtf8(IniPath());
    if (text.empty()) return;

    CaConfig *cur = &s.defaults;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, (nl == std::string::npos) ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[' && line.back() == ']') {
            std::string name = line.substr(1, line.size() - 2);
            if (name == "default" || name.empty()) {
                cur = &s.defaults;
            } else if (name.compare(0, 3, "ca:") == 0) {
                std::string ca = name.substr(3);
                wchar_t w[MAX_PATH * 2];
                if (MultiByteToWideChar(CP_UTF8, 0, ca.c_str(), -1, w, _countof(w)) > 0)
                    cur = &s.cas[std::wstring(w)];
                else
                    cur = &s.defaults;
            } else {
                cur = NULL;      // 未知分段：忽略其内容
            }
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
        if (cur) ApplyKey(*cur, k, v);
    }
}

void EnsureLoadedLocked(Store &s)
{
    if (s.loaded) return;
    s.loaded = true;
    LoadLocked(s);
}

std::string Narrow(const std::wstring &w)
{
    char buf[MAX_PATH * 4] = {0};
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, buf, sizeof(buf) - 1, NULL, NULL);
    return std::string(buf);
}

bool WriteFileLocked(Store &s)
{
    std::string body;
    body += "# OcspDbProvider - CA certificate database revocation provider\r\n";
    body += "# [default] applies to every CA, [ca:<ca-id>] overrides one responder.\r\n";
    body += "# snapshot is optional: the default is <install>\\data\\<safe-ca-id>.dat\r\n";
    body += "[default]\r\n";

    char num[64];
    if (!s.defaults.snapshot.empty()) { body += "snapshot="; body += Narrow(s.defaults.snapshot); body += "\r\n"; }
    if (s.defaults.checkSeconds  >= 0) { sprintf_s(num, "%d", s.defaults.checkSeconds);  body += "checkseconds=";  body += num; body += "\r\n"; }
    if (s.defaults.validStatus   >= 0) { sprintf_s(num, "%d", s.defaults.validStatus);   body += "validstatus=";   body += num; body += "\r\n"; }
    if (s.defaults.revokedStatus >= 0) { sprintf_s(num, "%d", s.defaults.revokedStatus); body += "revokedstatus="; body += num; body += "\r\n"; }
    if (s.defaults.unknownStatus >= 0) { sprintf_s(num, "%d", s.defaults.unknownStatus); body += "unknownstatus="; body += num; body += "\r\n"; }

    for (std::map<std::wstring, CaConfig>::const_iterator it = s.cas.begin(); it != s.cas.end(); ++it) {
        body += "\r\n[ca:"; body += Narrow(it->first); body += "]\r\n";
        const CaConfig &c = it->second;
        if (!c.snapshot.empty()) { body += "snapshot="; body += Narrow(c.snapshot); body += "\r\n"; }
        if (c.checkSeconds  >= 0) { sprintf_s(num, "%d", c.checkSeconds);  body += "checkseconds=";  body += num; body += "\r\n"; }
        if (c.validStatus   >= 0) { sprintf_s(num, "%d", c.validStatus);   body += "validstatus=";   body += num; body += "\r\n"; }
        if (c.revokedStatus >= 0) { sprintf_s(num, "%d", c.revokedStatus); body += "revokedstatus="; body += num; body += "\r\n"; }
        if (c.unknownStatus >= 0) { sprintf_s(num, "%d", c.unknownStatus); body += "unknownstatus="; body += num; body += "\r\n"; }
        if (c.responseSeconds >= 0) { sprintf_s(num, "%d", c.responseSeconds); body += "responseseconds="; body += num; body += "\r\n"; }
    }

    return WriteTextFileUtf8(IniPath(), body);
}

} // namespace

// ------------------------------------------------------------------ 对外 API

Settings ConfigEffectiveFor(const std::wstring &caId)
{
    Settings st;
    Store &s = S();
    EnterCriticalSection(&s.cs);
    EnsureLoadedLocked(s);

    const CaConfig *d = &s.defaults;
    std::map<std::wstring, CaConfig>::const_iterator it = s.cas.find(caId);
    const CaConfig *c = (it != s.cas.end()) ? &it->second : NULL;

    st.checkSeconds  = (c && c->checkSeconds  >= 0) ? c->checkSeconds  : (d->checkSeconds  >= 0 ? d->checkSeconds  : 2);
    st.validStatus   = (c && c->validStatus   >= 0) ? c->validStatus   : (d->validStatus   >= 0 ? d->validStatus   : 0);
    st.revokedStatus = (c && c->revokedStatus >= 0) ? c->revokedStatus : (d->revokedStatus >= 0 ? d->revokedStatus : 1);
    st.unknownStatus = (c && c->unknownStatus >= 0) ? c->unknownStatus : (d->unknownStatus >= 0 ? d->unknownStatus : 0);
    st.responseSeconds = (c && c->responseSeconds >= 0) ? c->responseSeconds : (d->responseSeconds >= 0 ? d->responseSeconds : 60);

    std::wstring snap = (c && !c->snapshot.empty()) ? c->snapshot : d->snapshot;
    LeaveCriticalSection(&s.cs);

    if (snap.empty()) snap = JoinPath(DataDir(), SafeFileName(caId) + L".dat");
    st.snapshot = snap;

    if (st.checkSeconds < 0) st.checkSeconds = 0;
    if (st.checkSeconds > 3600) st.checkSeconds = 3600;
    if (st.responseSeconds < 10) st.responseSeconds = 10;
    if (st.responseSeconds > 3600) st.responseSeconds = 3600;
    return st;
}

bool ConfigSaveCa(const std::wstring &caId, const Settings &st)
{
    Store &s = S();
    EnterCriticalSection(&s.cs);
    EnsureLoadedLocked(s);
    CaConfig &c = s.cas[caId];
    c.snapshot      = st.snapshot;
    c.checkSeconds  = st.checkSeconds;
    c.validStatus   = st.validStatus;
    c.revokedStatus = st.revokedStatus;
    c.unknownStatus = st.unknownStatus;
    c.responseSeconds = st.responseSeconds;
    bool ok = WriteFileLocked(s);
    LeaveCriticalSection(&s.cs);
    return ok;
}

bool ConfigRemoveCa(const std::wstring &caId)
{
    Store &s = S();
    EnterCriticalSection(&s.cs);
    EnsureLoadedLocked(s);
    s.cas.erase(caId);
    bool ok = WriteFileLocked(s);
    LeaveCriticalSection(&s.cs);
    return ok;
}

std::vector<std::wstring> ConfigKnownCas()
{
    std::vector<std::wstring> out;
    Store &s = S();
    EnterCriticalSection(&s.cs);
    EnsureLoadedLocked(s);
    for (std::map<std::wstring, CaConfig>::const_iterator it = s.cas.begin(); it != s.cas.end(); ++it)
        out.push_back(it->first);
    LeaveCriticalSection(&s.cs);
    return out;
}

CaConfig ConfigDefaults()
{
    Store &s = S();
    EnterCriticalSection(&s.cs);
    EnsureLoadedLocked(s);
    CaConfig d = s.defaults;
    LeaveCriticalSection(&s.cs);
    return d;
}

void ConfigReload()
{
    Store &s = S();
    EnterCriticalSection(&s.cs);
    s.loaded = false;
    LeaveCriticalSection(&s.cs);
}
