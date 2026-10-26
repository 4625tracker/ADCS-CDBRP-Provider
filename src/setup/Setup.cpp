// Setup.cpp —— OcspDbProvider 的安装程序（原生 Win32 控制台，单文件、无外部依赖）
//
// 设计要点：
//   * 载荷（DLL / uitest.exe / 安装脚本 / 许可证）以 RCDATA 资源内嵌，运行时解到
//     %TEMP%\adcs-cdbrp-setup-<pid>，然后调用同一份 install.ps1 执行真正的安装；
//     安装逻辑只有一处实现（脚本），安装器只负责解包、提权和传参。
//   * 清单是 asInvoker：需要管理员时才用 ShellExecuteExW("runas") 自举提权，
//     因此 --extract-only / --list / -Mode status 这类只读操作不会弹 UAC。
//   * 退出码透传子进程的退出码，方便脚本化与 CI。
//
// 用法：
//   Setup.exe                       等价于 -Mode install
//   Setup.exe -Mode activate        切换响应程序到本提供程序
//   Setup.exe -Mode deactivate      回滚到内置 CRL 提供程序
//   Setup.exe -Mode uninstall       卸载（加 -RemoveFiles 连文件一起删）
//   Setup.exe -Mode status|sync|selftest
//   Setup.exe -CAConfig "SRV1\CORP-CA" -InstallDir "D:\ocsp" [-Rebuild 不可用]
//   Setup.exe --extract-only <dir>  只解出载荷（不需要管理员）
//   Setup.exe --list                列出载荷内容
//   Setup.exe --quiet               不询问确认
//   Setup.exe --keep-temp           保留临时目录（排错用）
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include "setup_version.h"      // 构建时生成：SETUP_VERSION / SETUP_ARCH / SETUP_ARCH_DIR

// ------------------------------------------------------------------ 载荷表
//
// 资源 ID 与 Setup.rc 一一对应（build-installer.ps1 生成 .rc）。

struct PayloadEntry {
    int id;
    const wchar_t *dest;        // 相对临时目录的路径
};

static const PayloadEntry kPayload[] = {
    { 1001, L"scripts\\install.ps1" },
    { 1002, L"scripts\\sync.ps1"    },
    { 1003, L"out\\" SETUP_ARCH_DIR L"\\OcspDbProvider.dll" },
    { 1004, L"out\\" SETUP_ARCH_DIR L"\\uitest.exe"         },
    { 1005, L"LICENSE.txt"          },
    { 1006, L"out\\" SETUP_ARCH_DIR L"\\OcspConfig.exe"     },
};

static const int kPayloadCount = (int)(sizeof(kPayload) / sizeof(kPayload[0]));

// ------------------------------------------------------------------ 小工具

static void Print(const wchar_t *fmt, ...)
{
    wchar_t buf[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    wprintf(L"%s\n", buf);
    fflush(stdout);
}

static std::wstring ExePath()
{
    wchar_t p[MAX_PATH * 2] = {0};
    GetModuleFileNameW(NULL, p, _countof(p));
    return std::wstring(p);
}

static std::wstring ExeDir()
{
    std::wstring p = ExePath();
    size_t pos = p.find_last_of(L'\\');
    return (pos == std::wstring::npos) ? std::wstring() : p.substr(0, pos);
}

static bool IsAdmin()
{
    BOOL admin = FALSE;
    PSID group = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &group)) {
        CheckTokenMembership(NULL, group, &admin);
        FreeSid(group);
    }
    return admin != FALSE;
}

static bool EnsureDir(const std::wstring &path)
{
    if (path.empty()) return false;
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    size_t slash = path.find_last_of(L'\\');
    if (slash != std::wstring::npos && slash > 2) {
        if (!EnsureDir(path.substr(0, slash))) return false;
    }
    return CreateDirectoryW(path.c_str(), NULL) != FALSE ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool WriteBytes(const std::wstring &path, const BYTE *data, DWORD size)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(h, data, size, &written, NULL) && written == size;
    CloseHandle(h);
    return ok;
}

static bool ExtractOne(int id, const std::wstring &dest)
{
    HRSRC hr = FindResourceW(NULL, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!hr) { Print(L"  payload resource %d not found", id); return false; }
    DWORD size = SizeofResource(NULL, hr);
    HGLOBAL hg = LoadResource(NULL, hr);
    if (!hg) { Print(L"  payload resource %d failed to load", id); return false; }
    const BYTE *data = (const BYTE *)LockResource(hg);
    if (!data && size > 0) { Print(L"  payload resource %d failed to lock", id); return false; }
    if (!EnsureDir(dest.substr(0, dest.find_last_of(L'\\')))) {
        Print(L"  cannot create directory for %s", dest.c_str());
        return false;
    }
    if (!WriteBytes(dest, data, size)) {
        Print(L"  cannot write %s (error %lu)", dest.c_str(), GetLastError());
        return false;
    }
    Print(L"  %-52s %8lu B", dest.c_str(), size);
    return true;
}

static void RemoveTree(const std::wstring &dir)
{
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring child = dir + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveTree(child);
            else {
                SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(child.c_str());
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

static std::wstring Quote(const std::wstring &s)
{
    return L"\"" + s + L"\"";
}

static bool NeedsAdmin(const std::wstring &mode)
{
    return mode == L"install" || mode == L"activate" || mode == L"deactivate" ||
           mode == L"uninstall" || mode == L"sync";
}

static bool NeedsConfirm(const std::wstring &mode)
{
    return mode == L"install" || mode == L"uninstall";
}

static int RunChild(const std::wstring &app, std::wstring cmdline)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(0);

    if (!CreateProcessW(app.c_str(), buf.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        Print(L"cannot start %s (error %lu)", app.c_str(), GetLastError());
        return 3;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

// 用 runas 重新启动自己，把原始参数原样带过去
static int RelaunchElevated(int argc, wchar_t **argv)
{
    std::wstring params;
    for (int i = 1; i < argc; i++) {
        if (!params.empty()) params += L" ";
        std::wstring a = argv[i];
        if (a.find(L' ') != std::wstring::npos) a = Quote(a);
        params += a;
    }

    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    std::wstring exe = ExePath();
    sei.lpFile = exe.c_str();
    sei.lpParameters = params.empty() ? NULL : params.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        Print(L"elevation failed (error %lu). Right-click the setup and choose 'Run as administrator'.",
              GetLastError());
        return 5;
    }
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return (int)code;
}

static void PrintHelp()
{
    Print(L"ADCS CDBRP Provider Setup %s (%s)", SETUP_VERSION, SETUP_ARCH);
    Print(L"");
    Print(L"  Setup.exe [options]");
    Print(L"");
    Print(L"  -Mode install|activate|deactivate|uninstall|status|sync|selftest");
    Print(L"                 (default: install)");
    Print(L"  -CAConfig <ca> CA name or HOST\\CA-NAME (default: auto-detect)");
    Print(L"  -InstallDir <dir>  install directory (default: %%ProgramData%%\\OcspDbProvider)");
    Print(L"  -SyncPerMinute <1-6>  snapshot refreshes per minute (default 3, implemented as staggered triggers)");
    Print(L"  -RemoveFiles   with -Mode uninstall: delete the install directory too");
    Print(L"  --quiet        do not ask for confirmation");
    Print(L"  --keep-temp    keep the extracted payload directory");
    Print(L"  --extract-only <dir>  only extract the payload (no elevation, no install)");
    Print(L"  --list         list the embedded payload");
    Print(L"  --help         this text");
}

int wmain(int argc, wchar_t **argv)
{
    // 控制台按 UTF-8 输出，避免中文路径/参数在重定向时丢字
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);

    std::wstring mode = L"install";
    std::wstring caConfig;
    std::wstring installDir;
    std::wstring syncPerMinute;
    std::wstring extractOnly;
    bool removeFiles = false;
    bool quiet = false;
    bool keepTemp = false;
    bool listOnly = false;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h" || a == L"/?") { PrintHelp(); return 0; }
        else if (a == L"--list") listOnly = true;
        else if (a == L"--quiet" || a == L"-y") quiet = true;
        else if (a == L"--keep-temp") keepTemp = true;
        else if (a == L"-RemoveFiles") removeFiles = true;
        else if (a == L"-Mode" && i + 1 < argc) mode = argv[++i];
        else if (a == L"-CAConfig" && i + 1 < argc) caConfig = argv[++i];
        else if (a == L"-InstallDir" && i + 1 < argc) installDir = argv[++i];
        else if (a == L"-SyncPerMinute" && i + 1 < argc) syncPerMinute = argv[++i];
        else if (a == L"--extract-only" && i + 1 < argc) extractOnly = argv[++i];
        else { Print(L"unknown option: %s (try --help)", a.c_str()); return 2; }
    }

    const std::wstring validModes[] = { L"install", L"activate", L"deactivate", L"uninstall",
                                        L"status", L"sync", L"selftest" };
    bool modeOk = false;
    for (int i = 0; i < (int)(sizeof(validModes) / sizeof(validModes[0])); i++)
        if (mode == validModes[i]) modeOk = true;

    Print(L"ADCS CDBRP Provider Setup %s (%s)", SETUP_VERSION, SETUP_ARCH);
    Print(L"");

    if (listOnly) {
        Print(L"embedded payload:");
        for (int i = 0; i < kPayloadCount; i++)
            Print(L"  %d  %s", kPayload[i].id, kPayload[i].dest);
        return 0;
    }
    if (!modeOk) { Print(L"invalid -Mode: %s (try --help)", mode.c_str()); return 2; }

    // 目标目录
    std::wstring tempRoot;
    if (!extractOnly.empty()) {
        tempRoot = extractOnly;
    } else {
        wchar_t tmp[MAX_PATH * 2] = {0};
        GetTempPathW(_countof(tmp), tmp);
        wchar_t name[64];
        _snwprintf_s(name, _countof(name), _TRUNCATE, L"adcs-cdbrp-setup-%lu", GetCurrentProcessId());
        tempRoot = std::wstring(tmp) + name;
    }

    Print(L"extracting payload to %s", tempRoot.c_str());
    RemoveTree(tempRoot);           // 上一次失败的残留
    if (!EnsureDir(tempRoot)) { Print(L"cannot create %s", tempRoot.c_str()); return 4; }

    for (int i = 0; i < kPayloadCount; i++) {
        if (!ExtractOne(kPayload[i].id, tempRoot + L"\\" + kPayload[i].dest)) {
            Print(L"payload extraction failed; setup aborted");
            return 4;
        }
    }

    if (!extractOnly.empty()) {
        Print(L"");
        Print(L"payload extracted (no installation performed)");
        return 0;
    }

    // 需要管理员时自举提权
    if (NeedsAdmin(mode) && !IsAdmin()) {
        Print(L"administrator rights required for -Mode %s: re-launching elevated...", mode.c_str());
        int rc = RelaunchElevated(argc, argv);
        if (!keepTemp) RemoveTree(tempRoot);
        return rc;
    }

    // 确认
    if (NeedsConfirm(mode) && !quiet) {
        Print(L"");
        if (mode == L"install")
            Print(L"This will install the OCSP CA-database revocation provider into:");
        else
            Print(L"This will UNINSTALL the provider from:");
        if (!installDir.empty()) Print(L"  %s", installDir.c_str());
        else Print(L"  %%ProgramData%%\\OcspDbProvider");
        Print(L"");
        wprintf(L"Continue? [Y/n] ");
        fflush(stdout);
        wchar_t answer[16] = {0};
        if (!fgetws(answer, _countof(answer), stdin)) answer[0] = 0;
        if (answer[0] == L'n' || answer[0] == L'N') { Print(L"cancelled"); return 1; }
    }

    // 组装 install.ps1 的命令行
    std::wstring ps = std::wstring(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring script = tempRoot + L"\\scripts\\install.ps1";
    std::wstring cmd = Quote(ps) + L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                       Quote(script) + L" -Mode " + mode;
    if (!caConfig.empty())   cmd += L" -CAConfig " + Quote(caConfig);
    if (!installDir.empty()) cmd += L" -InstallDir " + Quote(installDir);
    if (!syncPerMinute.empty()) cmd += L" -SyncPerMinute " + Quote(syncPerMinute);
    if (removeFiles)         cmd += L" -RemoveFiles";

    Print(L"");
    Print(L"running: install.ps1 -Mode %s", mode.c_str());
    Print(L"------------------------------------------------------------------");
    int rc = RunChild(ps, cmd);
    Print(L"------------------------------------------------------------------");

    if (!keepTemp) RemoveTree(tempRoot);
    else Print(L"payload kept at %s", tempRoot.c_str());

    if (rc == 0) Print(L"setup finished successfully (%s)", mode.c_str());
    else         Print(L"setup failed: exit code %d", rc);
    return rc;
}
