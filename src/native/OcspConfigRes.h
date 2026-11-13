// OcspConfigRes.h - dialog and control IDs for OcspConfig.exe
//
// Keep this file pure ASCII: rc.exe reads include files with the ANSI code page,
// and a GBK trail byte of 0x5C inside a Chinese comment swallows the next line.
#pragma once

#define IDD_MANAGE_ZH        201
#define IDD_MANAGE_EN        202

#define IDC_LIST_CA          2001
#define IDC_EDIT_CA          2002
#define IDC_EDIT_SNAP        2003
#define IDC_BTN_BROWSE       2004
#define IDC_EDIT_CHECK       2005
// 2006 / 2007 / 2008 used to be the three status-code edit boxes. The mapping now
// lives only in provider.ini (not exposed in the UI); the IDs stay reserved.
// #define IDC_EDIT_VALID    2006
// #define IDC_EDIT_REVOKED  2007
// #define IDC_EDIT_UNKNOWN  2008
#define IDC_STATIC_STATE     2009
#define IDC_BTN_SAVE         2010
#define IDC_BTN_DELETE       2011
#define IDC_BTN_REFRESH      2012
#define IDC_BTN_CLOSE        2013

// 2.2.0: the UI focuses on "CA / snapshot" and "OCSP response"
#define IDC_EDIT_RESP        2014
#define IDC_STATIC_LATENCY   2015
#define IDC_BTN_P10          2016
#define IDC_BTN_P20          2017
#define IDC_BTN_P30          2018
#define IDC_BTN_P60          2019
