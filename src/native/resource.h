// resource.h —— 对话框与控件 ID（.rc 与 .cpp 共用）
#pragma once

// 两种语言的对话框各一份，由代码按 UI 语言选择（比依赖 LANGUAGE 资源块确定）
#define IDD_CONFIG_ZH           101
#define IDD_CONFIG_EN           102

#define IDC_EDIT_PATH           1001
#define IDC_BTN_BROWSE          1002
#define IDC_EDIT_MAXAGE         1003
#define IDC_EDIT_VALID          1004
#define IDC_EDIT_REVOKED        1005
#define IDC_EDIT_UNKNOWN        1006
#define IDC_STATIC_STATUS       1007
#define IDC_BTN_RELOAD          1008
