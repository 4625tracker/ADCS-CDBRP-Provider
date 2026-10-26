// OcspConfig.cpp —— 多 CA 配置工具（OcspConfig.exe）
//
// 用途：给 OcspDbProvider 批量/逐个 CA 配置快照路径与状态码映射，并显示每个 CA 的
// 快照状态（路径、是否存在、行数、修改时间）。配置读写与提供程序共用 OcspDbConfig，
// 因此两边对 provider.ini 的理解永远一致。
//
// 用法：
//   OcspConfig.exe                          打开图形界面
//   OcspConfig.exe --dump                   打印所有 CA 的生效配置与快照状态
//   OcspConfig.exe --set <ca> [--snapshot <path>] [--check N] [--valid N] [--revoked N] [--unknown N]
//                                           非交互修改单个 CA（未给出的项保持原生效值）
//   OcspConfig.exe --remove <ca>            删除该 CA 的分段
//   OcspConfig.exe --selftest               打开窗口、导出控件树、自动关闭（无头冒烟测试）
//   OcspConfig.exe --lang zh|en             强制界面语言
#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <algorithm>
#include "OcspDbConfig.h"
#include "OcspConfigRes.h"

// ------------------------------------------------------------------ 基础输出

static void Print(const wchar_t *fmt, ...)
{
    wchar_t buf[8192];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    // stdout 是文本模式，字符串里的 \r\n 会被翻成 \r\r\n；统一去掉 \r
    std::wstring line(buf);
    line.erase(std::remove(line.begin(), line.end(), L'\r'), line.end());
    wprintf(L"%s\n", line.c_str());
    fflush(stdout);
}

// ------------------------------------------------------------------ 快照统计

struct SnapInfo {
    bool exists = false;
    bool loaded = false;
    unsigned long long size = 0;
    size_t rows = 0;
    SYSTEMTIME mtime;
    bool hasMtime = false;
    std::wstring hint;
};

static SnapInfo InspectSnapshot(const std::wstring &path)
{
    SnapInfo info;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        info.hint = Tr(L"文件不存在：检查计划任务是否在跑、路径是否正确。",
                       L"File not found: check the scheduled task and the path.");
        return info;
    }
    info.exists = true;
    info.size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&fad.ftLastWriteTime, &ftLocal);
    FileTimeToSystemTime(&ftLocal, &info.mtime);
    info.hasMtime = true;

    std::string text = ReadTextFileUtf8(path);
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        int fields = 1;
        for (char c : line) if (c == '\t') fields++;
        if (fields >= 3) info.rows++;
    }
    info.loaded = info.rows > 0;

    if (info.rows == 0) {
        if (info.size == 0)
            info.hint = Tr(L"文件是空的（0 字节）：同步任务没有写入任何内容。",
                           L"The file is empty (0 bytes): the sync task wrote nothing.");
        else
            info.hint = Tr(L"文件存在但没有可解析的行：每行需要「序列号<TAB>处置<TAB>吊销时间」，"
                           L"可能是导出失败或格式不对。",
                           L"The file exists but has no parsable rows: each line needs "
                           L"serial<TAB>disposition<TAB>revokedWhen. The export may have failed.");
    }
    return info;
}

static std::wstring StateText(const std::wstring &ca, const Settings &st)
{
    SnapInfo s = InspectSnapshot(st.snapshot);
    wchar_t buf[2048];
    std::wstring text;

    _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"CA：%s\r\n", L"CA: %s\r\n"),
                 ca.empty() ? L"(none)" : ca.c_str());
    text += buf;
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"快照文件：%s\r\n", L"Snapshot file: %s\r\n"), st.snapshot.c_str());
    text += buf;
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"文件状态：%s\r\n", L"File state: %s\r\n"),
                 s.exists ? Tr(L"存在", L"exists") : Tr(L"不存在", L"missing"));
    text += buf;
    if (s.exists) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"大小：%llu 字节\r\n", L"Size: %llu bytes\r\n"), s.size);
        text += buf;
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"可解析记录：%Iu 行\r\n", L"Parsable rows: %Iu\r\n"), s.rows);
        text += buf;
        if (s.hasMtime) {
            _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                         Tr(L"修改时间：%04u-%02u-%02u %02u:%02u:%02u\r\n", L"Modified: %04u-%02u-%02u %02u:%02u:%02u\r\n"),
                         s.mtime.wYear, s.mtime.wMonth, s.mtime.wDay, s.mtime.wHour, s.mtime.wMinute, s.mtime.wSecond);
            text += buf;
        }
    }
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"缓存：%d 秒\r\n", L"Cache: %d s\r\n"), st.checkSeconds);
    text += buf;
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, Tr(L"状态码：有效=%d 已吊销=%d 未知=%d\r\n",
                                                   L"Status codes: valid=%d revoked=%d unknown=%d\r\n"),
                 st.validStatus, st.revokedStatus, st.unknownStatus);
    text += buf;
    if (!s.hint.empty()) { text += L"\r\n"; text += s.hint; }
    return text;
}

// ------------------------------------------------------------------ CA 发现

struct CaRow {
    std::wstring id;
    bool configured = false;
    bool responder = false;
};

static std::vector<std::wstring> EnumerateResponderCas()
{
    std::vector<std::wstring> out;
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\OCSPSvc\\Responder",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return out;
    for (DWORD i = 0;; i++) {
        wchar_t name[512] = {0};
        DWORD len = _countof(name);
        FILETIME ft;
        if (RegEnumKeyExW(hk, i, name, &len, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) break;
        out.push_back(name);
    }
    RegCloseKey(hk);
    return out;
}

static std::vector<CaRow> CollectCas()
{
    std::vector<CaRow> rows;
    std::vector<std::wstring> configured = ConfigKnownCas();
    std::vector<std::wstring> responder = EnumerateResponderCas();

    for (size_t i = 0; i < configured.size(); i++) {
        CaRow r;
        r.id = configured[i];
        r.configured = true;
        r.responder = std::find(responder.begin(), responder.end(), r.id) != responder.end();
        rows.push_back(r);
    }
    for (size_t i = 0; i < responder.size(); i++) {
        bool seen = false;
        for (size_t j = 0; j < rows.size(); j++) if (rows[j].id == responder[i]) seen = true;
        if (!seen) {
            CaRow r;
            r.id = responder[i];
            r.responder = true;
            rows.push_back(r);
        }
    }
    std::sort(rows.begin(), rows.end(), [](const CaRow &a, const CaRow &b) { return a.id < b.id; });
    return rows;
}

// ------------------------------------------------------------------ 图形界面

struct UiState {
    std::vector<CaRow> rows;
};

static void RefreshList(HWND hDlg, UiState *ui, const std::wstring &keep)
{
    HWND list = GetDlgItem(hDlg, IDC_LIST_CA);
    SendMessageW(list, LB_RESETCONTENT, 0, 0);
    ui->rows = CollectCas();

    int select = -1;
    for (size_t i = 0; i < ui->rows.size(); i++) {
        std::wstring label = ui->rows[i].id;
        if (ui->rows[i].responder) label += Tr(L"  [响应程序]", L"  [responder]");
        if (ui->rows[i].configured) label += Tr(L"  [已配置]", L"  [configured]");
        SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)label.c_str());
        if (!keep.empty() && ui->rows[i].id == keep) select = (int)i;
    }
    if (select < 0 && !ui->rows.empty()) select = 0;
    if (select >= 0) {
        SendMessageW(list, LB_SETCURSEL, select, 0);
        SendMessageW(hDlg, WM_COMMAND, MAKEWPARAM(IDC_LIST_CA, LBN_SELCHANGE), (LPARAM)list);
    }
}

static void LoadCaIntoFields(HWND hDlg, const std::wstring &ca)
{
    Settings st = ConfigEffectiveFor(ca);
    SetDlgItemTextW(hDlg, IDC_EDIT_CA, ca.c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_SNAP, st.snapshot.c_str());
    wchar_t num[16];
    _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st.checkSeconds);
    SetDlgItemTextW(hDlg, IDC_EDIT_CHECK, num);
    _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st.validStatus);
    SetDlgItemTextW(hDlg, IDC_EDIT_VALID, num);
    _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st.revokedStatus);
    SetDlgItemTextW(hDlg, IDC_EDIT_REVOKED, num);
    _snwprintf_s(num, _countof(num), _TRUNCATE, L"%d", st.unknownStatus);
    SetDlgItemTextW(hDlg, IDC_EDIT_UNKNOWN, num);
    SetDlgItemTextW(hDlg, IDC_STATIC_STATE, StateText(ca, st).c_str());
}

static std::wstring CurrentCa(HWND hDlg)
{
    wchar_t buf[512] = {0};
    GetDlgItemTextW(hDlg, IDC_EDIT_CA, buf, _countof(buf));
    return std::wstring(buf);
}

static Settings ReadFields(HWND hDlg)
{
    Settings st;
    wchar_t path[MAX_PATH * 3] = {0};
    GetDlgItemTextW(hDlg, IDC_EDIT_SNAP, path, _countof(path));
    st.snapshot = path;
    st.checkSeconds  = (int)GetDlgItemInt(hDlg, IDC_EDIT_CHECK,   NULL, FALSE);
    st.validStatus   = (int)GetDlgItemInt(hDlg, IDC_EDIT_VALID,   NULL, FALSE);
    st.revokedStatus = (int)GetDlgItemInt(hDlg, IDC_EDIT_REVOKED, NULL, FALSE);
    st.unknownStatus = (int)GetDlgItemInt(hDlg, IDC_EDIT_UNKNOWN, NULL, FALSE);
    if (st.checkSeconds < 0) st.checkSeconds = 0;
    if (st.checkSeconds > 3600) st.checkSeconds = 3600;
    return st;
}

static void DumpControls(HWND hDlg)
{
    Print(L"dialog rect:");
    RECT rc;
    GetWindowRect(hDlg, &rc);
    Print(L"  (%ld,%ld)-(%ld,%ld)", rc.left, rc.top, rc.right, rc.bottom);
    for (HWND h = GetWindow(hDlg, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT)) {
        wchar_t cls[64] = {0}, text[512] = {0};
        GetClassNameW(h, cls, _countof(cls));
        GetWindowTextW(h, text, _countof(text));
        Print(L"  id=%-5d class=%-12s text=%s", GetDlgCtrlID(h), cls, text);
    }
}

static INT_PTR CALLBACK ManageDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    UiState *ui = (UiState *)GetWindowLongPtrW(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG:
    {
        ui = (UiState *)lp;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)ui);
        RefreshList(hDlg, ui, std::wstring());
        wchar_t cap[8] = {0};
        if (GetEnvironmentVariableW(L"OCSPCONFIG_CAPTURE", cap, _countof(cap)) > 0 && cap[0] == L'1')
            SetTimer(hDlg, 1, 600, NULL);
        return TRUE;
    }
    case WM_TIMER:
        if (wp == 1) {
            KillTimer(hDlg, 1);
            DumpControls(hDlg);
            PostMessageW(hDlg, WM_COMMAND, IDCANCEL, 0);
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_LIST_CA:
            if (HIWORD(wp) == LBN_SELCHANGE) {
                int idx = (int)SendDlgItemMessageW(hDlg, IDC_LIST_CA, LB_GETCURSEL, 0, 0);
                if (idx >= 0 && ui && idx < (int)ui->rows.size())
                    LoadCaIntoFields(hDlg, ui->rows[idx].id);
                return TRUE;
            }
            return FALSE;

        case IDC_BTN_REFRESH:
            RefreshList(hDlg, ui, CurrentCa(hDlg));
            return TRUE;

        case IDC_BTN_BROWSE:
        {
            wchar_t path[MAX_PATH * 3] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_SNAP, path, _countof(path));
            OPENFILENAMEW ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hDlg;
            ofn.lpstrFile = path;
            ofn.nMaxFile = _countof(path);
            ofn.lpstrFilter = Tr(L"快照文件 (*.dat)\0*.dat\0所有文件 (*.*)\0*.*\0\0",
                                 L"Snapshot files (*.dat)\0*.dat\0All files (*.*)\0*.*\0\0");
            ofn.lpstrTitle = Tr(L"选择该 CA 的证书数据库快照", L"Select the snapshot for this CA");
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                SetDlgItemTextW(hDlg, IDC_EDIT_SNAP, path);
                LoadCaIntoFields(hDlg, CurrentCa(hDlg));
            }
            return TRUE;
        }

        case IDC_BTN_SAVE:
        {
            std::wstring ca = CurrentCa(hDlg);
            if (ca.empty()) {
                MessageBoxW(hDlg, Tr(L"CA 名称不能为空。", L"The CA name cannot be empty."),
                            Tr(L"多 CA 配置", L"Multi-CA configuration"), MB_ICONWARNING);
                return TRUE;
            }
            Settings st = ReadFields(hDlg);
            if (st.snapshot.empty()) {
                MessageBoxW(hDlg, Tr(L"快照文件路径不能为空。", L"The snapshot path cannot be empty."),
                            Tr(L"多 CA 配置", L"Multi-CA configuration"), MB_ICONWARNING);
                return TRUE;
            }
            if (!ConfigSaveCa(ca, st)) {
                MessageBoxW(hDlg, Tr(L"写入 provider.ini 失败，请检查目录权限。",
                                     L"Failed to write provider.ini. Check the directory permissions."),
                            Tr(L"多 CA 配置", L"Multi-CA configuration"), MB_ICONERROR);
                return TRUE;
            }
            ConfigReload();
            RefreshList(hDlg, ui, ca);
            LoadCaIntoFields(hDlg, ca);
            MessageBoxW(hDlg, Tr(L"已保存。重启 OCSPSvc 后提供程序才能读到新配置。",
                                 L"Saved. Restart OCSPSvc so the provider picks up the new configuration."),
                        Tr(L"多 CA 配置", L"Multi-CA configuration"), MB_ICONINFORMATION);
            return TRUE;
        }

        case IDC_BTN_DELETE:
        {
            std::wstring ca = CurrentCa(hDlg);
            if (ca.empty()) return TRUE;
            if (MessageBoxW(hDlg,
                            Tr(L"从 provider.ini 删除该 CA 的分段？\n（不会触碰响应程序自身的配置）",
                               L"Remove this CA section from provider.ini?\n(The responder configuration is not touched.)"),
                            Tr(L"多 CA 配置", L"Multi-CA configuration"),
                            MB_ICONQUESTION | MB_YESNO) != IDYES)
                return TRUE;
            ConfigRemoveCa(ca);
            ConfigReload();
            RefreshList(hDlg, ui, std::wstring());
            return TRUE;
        }

        case IDCANCEL:
        case IDC_BTN_CLOSE:
            EndDialog(hDlg, 0);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

static int RunGui()
{
    UiState ui;
    HINSTANCE hInst = GetModuleHandleW(NULL);
    INT_PTR r = DialogBoxParamW(hInst, MAKEINTRESOURCEW(IsZhUi() ? IDD_MANAGE_ZH : IDD_MANAGE_EN),
                                NULL, ManageDlgProc, (LPARAM)&ui);
    if (r == -1) {
        Print(Tr(L"无法创建对话框（错误 %lu）", L"cannot create the dialog (error %lu)"), GetLastError());
        return 2;
    }
    return 0;
}

// ------------------------------------------------------------------ 无界面命令

static int DumpAll()
{
    Print(L"install dir : %s", InstallDir().c_str());
    Print(L"config file : %s%s", IniPath().c_str(),
          GetFileAttributesW(IniPath().c_str()) == INVALID_FILE_ATTRIBUTES ? L"  (missing)" : L"");
    CaConfig d = ConfigDefaults();
    Print(L"defaults    : snapshot=%s check=%d valid=%d revoked=%d unknown=%d",
          d.snapshot.empty() ? L"(per-CA)" : d.snapshot.c_str(),
          d.checkSeconds, d.validStatus, d.revokedStatus, d.unknownStatus);
    Print(L"");

    std::vector<CaRow> rows = CollectCas();
    if (rows.empty()) { Print(L"(no CA found: no responder config and no section in provider.ini)"); return 0; }

    Print(L"%-28s %-8s %-6s %-6s %-8s %-6s %-7s %-5s %s",
          L"CA", L"source", L"check", L"valid", L"revoked", L"unk", L"rows", L"resp", L"snapshot");
    for (size_t i = 0; i < rows.size(); i++) {
        Settings st = ConfigEffectiveFor(rows[i].id);
        SnapInfo s = InspectSnapshot(st.snapshot);
        const wchar_t *src = rows[i].configured && rows[i].responder ? L"both"
                             : rows[i].configured ? L"ini" : L"responder";
        wchar_t rowsText[32];
        if (!s.exists) wcscpy_s(rowsText, L"(no file)");
        else _snwprintf_s(rowsText, _countof(rowsText), _TRUNCATE, L"%Iu%s", s.rows,
                          s.rows == 0 ? L"!" : L"");
        Print(L"%-28s %-8s %-6d %-6d %-8d %-6d %-7s %-5d %s",
              rows[i].id.c_str(), src, st.checkSeconds, st.validStatus, st.revokedStatus,
              st.unknownStatus, rowsText, st.responseSeconds, st.snapshot.c_str());
    }
    return 0;
}

static int SetCa(const std::wstring &ca, const Settings &overrides, bool hasSnap, bool hasCheck,
                 bool hasValid, bool hasRevoked, bool hasUnknown, bool hasResponse)
{
    Settings st = ConfigEffectiveFor(ca);
    if (hasSnap)    st.snapshot      = overrides.snapshot;
    if (hasCheck)   st.checkSeconds  = overrides.checkSeconds;
    if (hasValid)   st.validStatus   = overrides.validStatus;
    if (hasRevoked) st.revokedStatus = overrides.revokedStatus;
    if (hasUnknown) st.unknownStatus = overrides.unknownStatus;
    if (hasResponse) st.responseSeconds = overrides.responseSeconds;

    if (!ConfigSaveCa(ca, st)) { Print(L"ERROR: cannot write %s", IniPath().c_str()); return 1; }
    ConfigReload();
    Print(L"saved %s -> %s", ca.c_str(), IniPath().c_str());
    return 0;
}

static void PrintHelp()
{
    Print(L"OcspConfig 2.1.0 - multi-CA configuration for the OCSP CA database revocation provider");
    Print(L"");
    Print(L"  OcspConfig.exe                       open the GUI");
    Print(L"  OcspConfig.exe --dump                print every CA with its effective settings");
    Print(L"  OcspConfig.exe --set <ca> [--snapshot <p>] [--check N] [--valid N] [--revoked N] [--unknown N] [--response N]");
    Print(L"  OcspConfig.exe --remove <ca>         delete that CA section");
    Print(L"  OcspConfig.exe --selftest            open, dump controls, close");
    Print(L"  OcspConfig.exe --lang zh|en          force the UI language");
}

static int RunApp(int argc, wchar_t **argv)
{

    std::wstring mode = L"gui";
    std::wstring ca;
    Settings ov;
    bool hasSnap = false, hasCheck = false, hasValid = false, hasRevoked = false, hasUnknown = false, hasResponse = false;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") { PrintHelp(); return 0; }
        else if (a == L"--dump") mode = L"dump";
        else if (a == L"--selftest") mode = L"selftest";
        else if (a == L"--remove") { mode = L"remove"; if (i + 1 < argc) ca = argv[++i]; }
        else if (a == L"--set") { mode = L"set"; if (i + 1 < argc) ca = argv[++i]; }
        else if (a == L"--lang" && i + 1 < argc) SetEnvironmentVariableW(L"OCSPDBPROVIDER_LANG", argv[++i]);
        else if (a == L"--snapshot" && i + 1 < argc) { ov.snapshot = argv[++i]; hasSnap = true; }
        else if (a == L"--check" && i + 1 < argc) { ov.checkSeconds = _wtoi(argv[++i]); hasCheck = true; }
        else if (a == L"--valid" && i + 1 < argc) { ov.validStatus = _wtoi(argv[++i]); hasValid = true; }
        else if (a == L"--revoked" && i + 1 < argc) { ov.revokedStatus = _wtoi(argv[++i]); hasRevoked = true; }
        else if (a == L"--unknown" && i + 1 < argc) { ov.unknownStatus = _wtoi(argv[++i]); hasUnknown = true; }
        else if (a == L"--response" && i + 1 < argc) { ov.responseSeconds = _wtoi(argv[++i]); hasResponse = true; }
        else if (a == L"--capture") SetEnvironmentVariableW(L"OCSPCONFIG_CAPTURE", L"1");
        else { Print(L"unknown option: %s (try --help)", a.c_str()); return 2; }
    }

    if (mode == L"dump") return DumpAll();
    if (mode == L"selftest") { SetEnvironmentVariableW(L"OCSPCONFIG_CAPTURE", L"1"); return RunGui(); }
    if (mode == L"set") {
        if (ca.empty()) { Print(L"--set needs a CA name"); return 2; }
        return SetCa(ca, ov, hasSnap, hasCheck, hasValid, hasRevoked, hasUnknown, hasResponse);
    }
    if (mode == L"remove") {
        if (ca.empty()) { Print(L"--remove needs a CA name"); return 2; }
        if (!ConfigRemoveCa(ca)) { Print(L"ERROR: cannot write %s", IniPath().c_str()); return 1; }
        ConfigReload();
        Print(L"removed %s", ca.c_str());
        return 0;
    }
    return RunGui();
}

// ------------------------------------------------------------------ 入口
//
// GUI 子系统：双击不闪黑框；从命令行启动时附着父控制台，让 --dump / --help 有输出。

static void PrepareConsole()
{
    // Only attach to the parent console when we have no usable stdout. If the caller
    // redirected output (cmd /c ... > file, Start-Process -RedirectStandardOutput) the
    // handle is already valid and reopening CONOUT$ would throw that redirection away.
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    bool haveStdout = (h != NULL && h != INVALID_HANDLE_VALUE);
    if (!haveStdout && AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE *f = NULL;
        _wfreopen_s(&f, L"CONOUT$", L"w", stdout);
        _wfreopen_s(&f, L"CONOUT$", L"w", stderr);
    }
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    PrepareConsole();

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = argv ? RunApp(argc, argv) : 2;
    if (argv) LocalFree(argv);
    return rc;
}
