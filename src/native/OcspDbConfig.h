// OcspDbConfig.h —— 提供程序与配置工具共用的配置模型
//
// 提供程序（OcspDbProvider.dll）和独立配置工具（OcspConfig.exe）必须对
// 「安装目录 / provider.ini 格式 / 每个 CA 的生效值」有一致的理解，
// 所以这部分从 DLL 里抽出来，编译进两边。
#pragma once

#include <windows.h>
#include <string>
#include <vector>

// 注册表根（安装目录保存在 HKLM\SOFTWARE\OcspDbProvider\InstallDir）
#define OCSPDB_REG_ROOT L"SOFTWARE\\OcspDbProvider"

// ------------------------------------------------------------------ 路径
//
// 安装目录解析顺序：环境变量 OCSPDBPROVIDER_DIR -> 注册表 InstallDir
// -> %ProgramData%\OcspDbProvider -> %ALLUSERSPROFILE%\OcspDbProvider -> 兜底常量
const std::wstring &InstallDir();
std::wstring IniPath();
std::wstring DataDir();
std::wstring SafeFileName(const std::wstring &s);

std::wstring TrimTrailingSlash(std::wstring s);
std::wstring JoinPath(const std::wstring &dir, const std::wstring &name);

// 供提供程序读快照、供配置工具读快照做统计
std::string ReadTextFileUtf8(const std::wstring &path);
bool WriteTextFileUtf8(const std::wstring &path, const std::string &text);

// ------------------------------------------------------------------ 界面语言
//
// 默认跟随系统 UI 语言，OCSPDBPROVIDER_LANG=zh|en 可强制（便于测试）
bool IsZhUi();
const wchar_t *Tr(const wchar_t *zh, const wchar_t *en);

// ------------------------------------------------------------------ 配置模型

// 单个 CA 的配置；-1 / 空串表示「沿用 [default]」
struct CaConfig {
    std::wstring snapshot;
    int checkSeconds   = -1;
    int validStatus    = -1;
    int revokedStatus  = -1;
    int unknownStatus  = -1;
};

// 合并后的生效配置
struct Settings {
    std::wstring snapshot;
    int checkSeconds  = 2;
    int validStatus   = 0;
    int revokedStatus = 1;
    int unknownStatus = 0;
};

// 合并规则：CA 段 > [default] > 内置默认；快照缺省为 <install>\data\<safe-ca>.dat
Settings ConfigEffectiveFor(const std::wstring &caId);

// 写入该 CA 的独立分段（会重写整个 provider.ini，其他分段原样保留）
bool ConfigSaveCa(const std::wstring &caId, const Settings &st);
bool ConfigRemoveCa(const std::wstring &caId);

// provider.ini 里出现过的 CA id（不含 [default]）
std::vector<std::wstring> ConfigKnownCas();

// [default] 段（供配置界面显示继承来源）
CaConfig ConfigDefaults();

// 丢弃内存缓存，下次访问重新读文件（外部改过 provider.ini 后调用）
void ConfigReload();
