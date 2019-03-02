/*
 * Copyright(C) 2000 ������ ���
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

/*
 * \file $RCSfile$
 * \version $Revision: 126987 $
 * \date $Date:: 2015-09-08 16:51:58 +0300#$
 * \author $Author: pav $
 */
/*!
 * \brief ��������� ����������������� (lock-free) ��������� ������.
 *
 * �������� ��������� ������� ����������������� ��������� ������ ������ CPC.
 */
#ifndef _LFMM_H_INCLUDED
#define _LFMM_H_INCLUDED

#include <wincspc.h>

#if defined(__cplusplus)
extern "C" {
#endif // defined(__cplusplus)

typedef struct CPC_LFMM_CONFIG_ {
    CPC_INTERLOCKED_FUNCS   interlockedFuncs;
    LPVOID		    Buffer;
    LONG		    Size;
    BOOL		    fSMP;
    BOOL		    fStat;
    LONG 		    *PoolSizes;
    DWORD		    nPools;
    DWORD		    nCPUs;
} CPC_LFMM_CONFIG, * LPCPC_LFMM_CONFIG;

typedef DWORD CPCAPI CPCInitMemoryLF_t(
    /* [out] */ LPCPC_MEMORY_ARENA* pArena,
    /* [in] */ LPCPC_LFMM_CONFIG pCfg
);

#if !defined(CSP_LITE) || defined(LINUX) || defined(SOLARIS)
	// ��� ������������� ���������, � ��� �� � Linux � Solaris
	// ������� �������� �����.
#elif defined(FREEBSD)
    // ?????
    #define LFMM_SEPARATE_NAMESPACE_BINDING 1
#elif !defined(UNIX)
    // #include "cpdrvlib.h"
    // IOCTL_GETCPCINITMEMORYLF
    #define LFMM_SEPARATE_NAMESPACE_BINDING 1
#endif

#if !defined(LFMM_SEPARATE_NAMESPACE_BINDING)
    CPCInitMemoryLF_t CPCInitMemoryLF;
#endif

#if defined(__cplusplus)
} // extern "C"
#endif // defined(__cplusplus)

#endif /* _LFMM_H_INCLUDED */
