// resource.h - dialog and control IDs shared by the .rc file and the .cpp code
//
// Keep this file pure ASCII: rc.exe reads include files with the ANSI code page,
// and a GBK trail byte of 0x5C inside a Chinese comment swallows the next line.
#pragma once

// One dialog per language; the code picks one explicitly by UI language
#define IDD_CONFIG_ZH           101
#define IDD_CONFIG_EN           102

#define IDC_EDIT_PATH           1001
#define IDC_BTN_BROWSE          1002
#define IDC_EDIT_MAXAGE         1003
// 1004 / 1005 / 1006 were the old status-code edit boxes. The mapping now lives
// only in provider.ini and is no longer exposed in the UI; the IDs stay reserved.
// #define IDC_EDIT_VALID       1004
// #define IDC_EDIT_REVOKED     1005
// #define IDC_EDIT_UNKNOWN     1006
#define IDC_STATIC_STATUS       1007
#define IDC_BTN_RELOAD          1008
#define IDC_EDIT_RESP           1009
