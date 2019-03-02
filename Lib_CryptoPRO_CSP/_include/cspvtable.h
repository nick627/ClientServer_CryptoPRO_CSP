/*
 * Copyright(C) 2000-2006 ������ ���
 *
 * ���� ���� �������� ����������, ����������
 * �������������� �������� ������ ���.
 *
 * ����� ����� ����� ����� �� ����� ���� �����������,
 * ����������, ���������� �� ������ �����,
 * ������������ ��� �������������� ����� ��������,
 * ���������������, �������� �� ���� � ��� ��
 * ����� ������������ ������� ��� ����������������
 * ���������� ���������� � ��������� ������ ���.
 */

/*!
 * \file $RCSfile$
 * \version $Revision: 126987 $
 * \date $Date:: 2015-09-08 16:51:58 +0300#$
 * \author $Author: pav $
 *
 * \brief ����������� VTABLEPROVSTRUC.
 *
 * �������� ����������� VTABLEPROVSTRUC � PVTABLEPROVSTRUC ��� �������������
 * � ������ ������������ ������.
 */
#ifndef _CSP_VTABLE_H_INCLUDED
#define _CSP_VTABLE_H_INCLUDED

#if defined(UNIX)
#include "CSP_WinDef.h"
#else // defined(UNIX)
#include <windef.h>
#endif // defined(UNIX)

#if defined(__cplusplus)
extern "C" {
#endif // defined(__cplusplus)

typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_A)(LPCSTR  szImage, CONST BYTE *pbSigData);
typedef void (WINAPI *CRYPT_RETURN_HWND)(HWND *phWnd);

typedef struct _VTABLEPROVSTRUC {
    DWORD   Version; 
    CRYPT_VERIFY_IMAGE_A FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD   dwProvType; 
    BYTE    *pbContextInfo; 
    DWORD   cbContextInfo;
    LPSTR   pszProvName;
} VTABLEPROVSTRUC, *PVTABLEPROVSTRUC;

#if defined(__cplusplus)
} // extern "C"
#endif // defined(__cplusplus)

#endif /* _CSP_VTABLE_H_INCLUDED */
